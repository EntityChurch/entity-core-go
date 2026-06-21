package continuation

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)



// --- helpers ---

// mergeResolution merges resolution data into params (both are CBOR maps).
func mergeResolution(params, resolution cbor.RawMessage) (cbor.RawMessage, error) {
	var paramsMap map[string]interface{}
	if err := cbor.Unmarshal(params, &paramsMap); err != nil {
		var genericMap map[interface{}]interface{}
		if err2 := cbor.Unmarshal(params, &genericMap); err2 != nil {
			return nil, fmt.Errorf("params must be a map for resolution merge")
		}
		paramsMap = make(map[string]interface{})
		for k, v := range genericMap {
			paramsMap[fmt.Sprint(k)] = v
		}
	}

	var resMap map[string]interface{}
	if err := cbor.Unmarshal(resolution, &resMap); err != nil {
		var genericMap map[interface{}]interface{}
		if err2 := cbor.Unmarshal(resolution, &genericMap); err2 != nil {
			return nil, fmt.Errorf("resolution must be a map")
		}
		resMap = make(map[string]interface{})
		for k, v := range genericMap {
			resMap[fmt.Sprint(k)] = v
		}
	}

	for k, v := range resMap {
		paramsMap[k] = v
	}

	result, err := ecf.Encode(paramsMap)
	if err != nil {
		return nil, fmt.Errorf("encode merged params: %w", err)
	}
	return cbor.RawMessage(result), nil
}

// readEntity reads an entity at the given path from the location index + content store.
func readEntity(hctx *handler.HandlerContext, path string) (entity.Entity, string) {
	contentHash, ok := hctx.LocationIndex.Get(path)
	if !ok {
		return entity.Entity{}, ""
	}
	ent, ok := hctx.Store.Get(contentHash)
	if !ok {
		return entity.Entity{}, ""
	}
	return ent, ent.Type
}

// getJoinLock returns the per-join-path mutex, creating one if needed.
func (h *Handler) getJoinLock(joinPath string) *sync.Mutex {
	h.mu.Lock()
	defer h.mu.Unlock()
	mu, ok := h.joinLocks[joinPath]
	if !ok {
		mu = &sync.Mutex{}
		h.joinLocks[joinPath] = mu
	}
	return mu
}

// applyTransform applies extract and select transforms to raw CBOR data.
// `included` is the envelope's `included` map, threaded so the
// deref_included transform_op can resolve a hash field to the entity at
// that hash. May be nil (e.g., test contexts with no envelope) — then
// deref_included is a total no-op.
func applyTransform(raw cbor.RawMessage, transform *types.ContinuationTransformData, included map[hash.Hash]entity.Entity) cbor.RawMessage {
	var value interface{}
	if err := cbor.Unmarshal(raw, &value); err != nil {
		return raw
	}

	if transform.Extract != "" {
		value = navigate(value, transform.Extract)
	}

	if len(transform.Select) > 0 {
		mapped := make(map[string]interface{})
		for dest, source := range transform.Select {
			mapped[dest] = navigate(value, source)
		}
		value = mapped
	}

	// transform_ops run after extract/select, before the *_extract fields
	// (EXTENSION-CONTINUATION §2.2 pipeline: extract -> select ->
	// transform_ops -> *_extract). Total/pure/bounded; never errors.
	if len(transform.TransformOps) > 0 {
		value = applyTransformOpsWithIncluded(value, transform.TransformOps, included)
	}

	result, err := ecf.Encode(value)
	if err != nil {
		return raw
	}
	return cbor.RawMessage(result)
}

// navigate walks a dotted path into an arbitrary value.
func navigate(value interface{}, dottedPath string) interface{} {
	if dottedPath == "" {
		return value
	}
	segments := strings.Split(dottedPath, ".")
	current := value
	for _, seg := range segments {
		if current == nil {
			return nil
		}
		switch m := current.(type) {
		case map[interface{}]interface{}:
			current = m[seg]
		case map[string]interface{}:
			current = m[seg]
		default:
			return nil
		}
	}
	return current
}

// mergeAssemble implements the §3.6 merge branch
// (PROPOSAL-CONTINUATION-MERGE-ASSEMBLY): shallow-merges the post-
// transform value (which MUST be a map) into the static params at top
// level, value keys winning on collision. Returns (merged_params,
// valueIsMap). When valueIsMap=false the merge degrades to no-op
// (static params only) and the caller binds the §3.4
// merge_value_not_map marker.
//
// Edge cases:
//   - cont.Params absent + map value      → final = value (merge into empty)
//   - cont.Params present + map value     → shallow merge, value keys win
//   - non-map value                       → final = params (or {} if no params)
//                                            + valueIsMap=false (caller binds marker)
func mergeAssemble(contParams cbor.RawMessage, value cbor.RawMessage) (cbor.RawMessage, bool) {
	// Decode value first; non-map → marker signal + static-only result.
	var valueDecoded interface{}
	if len(value) > 0 {
		if err := cbor.Unmarshal(value, &valueDecoded); err != nil {
			valueDecoded = nil
		}
	}
	valueMap, valueIsMap := normalizeToStringMap(valueDecoded)

	// Decode static params (may be absent).
	paramsMap := make(map[string]interface{})
	if len(contParams) > 0 {
		var raw map[string]interface{}
		if err := cbor.Unmarshal(contParams, &raw); err == nil {
			paramsMap = raw
		} else {
			var generic map[interface{}]interface{}
			if err := cbor.Unmarshal(contParams, &generic); err == nil {
				for k, v := range generic {
					paramsMap[fmt.Sprint(k)] = v
				}
			}
		}
	}

	if !valueIsMap {
		// Static-only fallback. Encode the params map back; if empty,
		// emit an empty CBOR map so the dispatched op receives a valid
		// (possibly empty) params payload.
		out, err := ecf.Encode(paramsMap)
		if err != nil {
			return contParams, false
		}
		return cbor.RawMessage(out), false
	}

	// Shallow merge: value keys win on collision.
	for k, v := range valueMap {
		paramsMap[k] = v
	}
	out, err := ecf.Encode(paramsMap)
	if err != nil {
		return contParams, true
	}
	return cbor.RawMessage(out), true
}

// normalizeToStringMap unwraps the two CBOR map shapes we see (string-
// keyed and generic-interface-keyed) into a string-keyed map. Returns
// (nil, false) if the value isn't a map at all.
func normalizeToStringMap(v interface{}) (map[string]interface{}, bool) {
	switch m := v.(type) {
	case map[string]interface{}:
		return m, true
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for k, vv := range m {
			out[fmt.Sprint(k)] = vv
		}
		return out, true
	default:
		return nil, false
	}
}

// bindMergeValueNotMapMarker writes a §3.4 chain-error-lost marker with
// reason="merge_value_not_map". The value's type name goes in
// OriginalCode (repurposed: there's no failed dispatch here, so the
// existing OriginalCode slot carries the diagnostic). OriginalStatus=0
// to distinguish from a real failed-dispatch marker. Purely
// observational — same contract as the other §3.4 reasons.
func (h *Handler) bindMergeValueNotMapMarker(hctx *handler.HandlerContext, contTarget string, value cbor.RawMessage) {
	var decoded interface{}
	typeName := "nil"
	if len(value) > 0 {
		if err := cbor.Unmarshal(value, &decoded); err == nil {
			typeName = goTypeName(decoded)
		} else {
			typeName = "undecodable"
		}
	}
	// v1.20 §3.10.6 timestamp-capture: origination is the moment we
	// observe the post-transform value isn't a map (i.e., right now).
	originTS := uint64(time.Now().UnixMilli())
	h.bindLostErrorMarker(hctx, contTarget, 0, nil, types.ChainErrorReasonMergeValueNotMap, originTS, hash.Hash{})
	_ = typeName // captured via marker's reason; type is observable in debug logs below.
	debugLog("merge_value_not_map: post-transform value type=%s (continuation target=%s)", typeName, contTarget)
}

// goTypeName returns a stable short name for a CBOR-decoded value.
func goTypeName(v interface{}) string {
	switch v.(type) {
	case nil:
		return "nil"
	case bool:
		return "bool"
	case string:
		return "string"
	case []byte:
		return "bytes"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return "int"
	case float32, float64:
		return "float"
	case []interface{}:
		return "array"
	case map[string]interface{}, map[interface{}]interface{}:
		return "map"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// assembleParams determines the dispatch mode and builds final params.
func assembleParams(contParams cbor.RawMessage, resultField string, value cbor.RawMessage) (cbor.RawMessage, error) {
	hasParams := len(contParams) > 0
	hasResultField := resultField != ""

	switch {
	case !hasParams && !hasResultField:
		// Pass-through: delivery result IS the params.
		return value, nil

	case hasParams && hasResultField:
		// Inject: params[result_field] = value.
		var paramsMap map[string]interface{}
		if err := cbor.Unmarshal(contParams, &paramsMap); err != nil {
			var genericMap map[interface{}]interface{}
			if err2 := cbor.Unmarshal(contParams, &genericMap); err2 != nil {
				return nil, fmt.Errorf("params must be a map for inject mode")
			}
			paramsMap = make(map[string]interface{})
			for k, v := range genericMap {
				paramsMap[fmt.Sprint(k)] = v
			}
		}
		var valueDecoded interface{}
		if err := cbor.Unmarshal(value, &valueDecoded); err != nil {
			valueDecoded = value
		}
		paramsMap[resultField] = valueDecoded

		result, err := ecf.Encode(paramsMap)
		if err != nil {
			return nil, fmt.Errorf("encode injected params: %w", err)
		}
		return cbor.RawMessage(result), nil

	case hasParams && !hasResultField:
		// Trigger: delivery result ignored.
		return contParams, nil

	default:
		// result_field without params — invalid.
		return nil, fmt.Errorf("result_field specified without params")
	}
}

func parentPath(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return ""
	}
	return p[:i]
}

func lastSegment(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return p
	}
	return p[i+1:]
}

func slotInExpected(slotName string, expected []string) bool {
	for _, e := range expected {
		if e == slotName {
			return true
		}
	}
	return false
}

func allSlotsReceived(expected []string, received map[string]cbor.RawMessage) bool {
	for _, e := range expected {
		if _, ok := received[e]; !ok {
			return false
		}
	}
	return true
}

func missingSlots(expected []string, received map[string]cbor.RawMessage) []string {
	var missing []string
	for _, e := range expected {
		if _, ok := received[e]; !ok {
			missing = append(missing, e)
		}
	}
	return missing
}
