package interop

import (
	"encoding/hex"
	"net"
	"os"
	"testing"
	"time"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/protocol"
	"go.entitychurch.org/entity-core-go/core/wire"

	"github.com/fxamacker/cbor/v2"
)

// TestInteropWireDiff captures and decodes the exact CBOR structures sent by
// each side to find spec ambiguities.
//
// INTEROP_ADDR=127.0.0.1:9001 go test -run TestInteropWireDiff -v
func TestInteropWireDiff(t *testing.T) {
	addr := os.Getenv("INTEROP_ADDR")
	if addr == "" {
		t.Skip("INTEROP_ADDR not set")
	}

	kp, _ := crypto.Generate()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// --- Go's hello EXECUTE ---
	helloEnv, _, _ := protocol.CreateHelloExecute(kp, []string{"entity-core/1.0"})
	goHelloBytes, _ := ecf.Encode(helloEnv)

	t.Log("======================================")
	t.Log("GO → PYTHON: Hello EXECUTE")
	t.Log("======================================")
	dumpCBOR(t, goHelloBytes, "")

	wire.WriteEnvelope(conn, helloEnv)

	// --- Python's hello EXECUTE ---
	pyHelloBytes, _ := wire.ReadFrame(conn)
	t.Log("")
	t.Log("======================================")
	t.Log("PYTHON → GO: Hello EXECUTE")
	t.Log("======================================")
	dumpCBOR(t, pyHelloBytes, "")

	// --- Go's authenticate EXECUTE ---
	// Extract their nonce.
	var pyHelloMap map[string]cbor.RawMessage
	ecf.Decode(pyHelloBytes, &pyHelloMap)
	var pyRoot map[string]cbor.RawMessage
	ecf.Decode(pyHelloMap["root"], &pyRoot)
	var pyData map[string]cbor.RawMessage
	ecf.Decode(pyRoot["data"], &pyData)
	var pyParams map[string]cbor.RawMessage
	ecf.Decode(pyData["params"], &pyParams)
	var pyParamsData map[string]cbor.RawMessage
	ecf.Decode(pyParams["data"], &pyParamsData)
	var theirNonce []byte
	ecf.Decode(pyParamsData["nonce"], &theirNonce)

	authEnv, _ := protocol.CreateAuthenticateExecute(kp, theirNonce)
	goAuthBytes, _ := ecf.Encode(authEnv)

	t.Log("")
	t.Log("======================================")
	t.Log("GO → PYTHON: Authenticate EXECUTE")
	t.Log("======================================")
	dumpCBOR(t, goAuthBytes, "")

	wire.WriteEnvelope(conn, authEnv)

	// --- Python's authenticate EXECUTE_RESPONSE ---
	pyAuthBytes, _ := wire.ReadFrame(conn)
	t.Log("")
	t.Log("======================================")
	t.Log("PYTHON → GO: Authenticate EXECUTE_RESPONSE")
	t.Log("======================================")
	dumpCBOR(t, pyAuthBytes, "")
}

// dumpCBOR decodes CBOR and prints it as a structured tree.
func dumpCBOR(t *testing.T, data []byte, indent string) {
	t.Helper()

	var v interface{}
	if err := ecf.Decode(data, &v); err != nil {
		t.Logf("%s[raw %d bytes]: %s", indent, len(data), hex.EncodeToString(data[:min(60, len(data))]))
		return
	}
	dumpValue(t, v, indent)
}

func dumpValue(t *testing.T, v interface{}, indent string) {
	t.Helper()
	switch val := v.(type) {
	case map[interface{}]interface{}:
		t.Logf("%smap(%d) {", indent, len(val))
		for k, v := range val {
			switch kk := k.(type) {
			case string:
				t.Logf("%s  %q:", indent, kk)
				dumpValue(t, v, indent+"    ")
			case []byte:
				t.Logf("%s  bytes(%d)=%s...:", indent, len(kk), hex.EncodeToString(kk[:min(16, len(kk))]))
				dumpValue(t, v, indent+"    ")
			default:
				t.Logf("%s  %v:", indent, k)
				dumpValue(t, v, indent+"    ")
			}
		}
		t.Logf("%s}", indent)
	case []interface{}:
		t.Logf("%sarray(%d) [", indent, len(val))
		for _, item := range val {
			dumpValue(t, item, indent+"  ")
		}
		t.Logf("%s]", indent)
	case string:
		if len(val) > 80 {
			t.Logf("%s%q...", indent, val[:80])
		} else {
			t.Logf("%s%q", indent, val)
		}
	case []byte:
		if len(val) > 40 {
			t.Logf("%sbytes(%d): %s...", indent, len(val), hex.EncodeToString(val[:40]))
		} else {
			t.Logf("%sbytes(%d): %s", indent, len(val), hex.EncodeToString(val))
		}
	case uint64:
		t.Logf("%suint: %d", indent, val)
	case int64:
		t.Logf("%sint: %d", indent, val)
	case bool:
		t.Logf("%sbool: %v", indent, val)
	case nil:
		t.Logf("%snull", indent)
	case float64:
		t.Logf("%sfloat: %v", indent, val)
	default:
		t.Logf("%s(%T) %v", indent, val, val)
	}
}
