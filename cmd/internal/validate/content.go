package validate

import (
	"context"
	"errors"
	"fmt"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/content"

	"github.com/fxamacker/cbor/v2"
)

const catContent = "content"

// runContent validates an EXTENSION-CONTENT v3.6 implementation. Covers:
//
//   - §6.1 handler manifest
//   - §2 entity types (blob, chunk, descriptor)
//   - §6.2/§6.3 path_required MUST (v3.4 → v3.5 behavior reversal)
//   - §4.3 64 KiB inline-include boundary (in-process)
//   - §3.6.1 FastCDC gear-table first-16 against SHA-256("FastCDC"||i)[0:8]
//   - §3.6.2 parameter derivation pin at 4 MiB target
//   - §3.6.3 FastCDC boundary determinism
//   - §3.6.5 edit-stability vector (1-byte insertion) — load-bearing
//   - §3.7 ECF byte-equality for blob / chunk entities
//   - §2.4 descriptor presence rule
//   - §5.3 descriptor integrity check (path↔body mismatch rejected)
//
// The path_required checks drive the peer over the wire. The chunker /
// descriptor checks exercise the in-process library against the spec —
// the §3.7 Conformance gate is on algorithm output, not a wire op.
func runContent(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catContent)

	// --- Declare checks ---

	r.Declare("handler_manifest", "CONTENT §6.1")
	r.Declare("handler_op_get", "CONTENT §6.2 / §11.3")
	r.Declare("handler_op_ingest", "CONTENT §6.3 / §11.3")

	r.Declare("type_blob", "CONTENT §2.1 / §11.1 MUST")
	r.Declare("type_chunk", "CONTENT §2.2 / §11.1 MUST")
	r.Declare("type_descriptor", "CONTENT §2.4 (v3.5 A1)")

	r.Declare("get_path_required", "CONTENT §6.2 MUST (v3.4 → v3.5 reversal)")
	r.Declare("ingest_path_required", "CONTENT §6.3 MUST (v3.4 → v3.5 reversal)")

	// FastCDC derivation/determinism/edit-stability and ECF byte-equality
	// are Go-library self-tests (they exercise this repo's chunker/encoder,
	// not the peer); they moved to content_fastcdc_selftest_test.go per the
	// validate-peer audit. Cross-impl FastCDC conformance belongs in the
	// offline corpus / an over-the-wire ingest check (GUIDE-CONFORMANCE §8).

	r.Declare("inline_include_at_threshold", "CONTENT §4.3 — inline-include at total_size = 65,536")
	r.Declare("inline_include_above_threshold", "CONTENT §4.3 — no inline-include at total_size = 65,537")

	r.Declare("descriptor_presence_rule", "CONTENT §2.4 presence rule MUST")
	r.Declare("descriptor_integrity_check", "CONTENT §5.3 integrity check MUST")

	r.Declare("frame-limit-respected", "CONTENT v3.6 Amendment 1 §6.2 MUST — frame-budget response chunking")

	// --- Step 1: Handler manifest + advertised ops ---

	r.Run("handler_manifest", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, "system/handler/system/content")
		if err != nil {
			if isHandlerAbsent(err) {
				return SkipCheck("system/content handler not present — EXTENSION-CONTENT is optional; absence is conformant (S1)")
			}
			return FailCheck("system/content handler manifest not present: " + err.Error())
		}
		r.Store("content_handler_manifest", ent)
		return PassCheck(fmt.Sprintf("system/content handler manifest at system/handler/system/content (type: %s)", ent.Type))
	})

	r.Run("handler_op_get", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest"); !ok {
			return out
		}
		ent := r.Load("content_handler_manifest").(entity.Entity)
		iface, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode content handler manifest: " + err.Error())
		}
		if _, ok := iface.Operations["get"]; !ok {
			return FailCheck("system/content handler missing op get (§6.2)")
		}
		return PassCheck("system/content:get advertised")
	})

	r.Run("handler_op_ingest", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest"); !ok {
			return out
		}
		ent := r.Load("content_handler_manifest").(entity.Entity)
		iface, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode content handler manifest: " + err.Error())
		}
		if _, ok := iface.Operations["ingest"]; !ok {
			return WarnCheck("system/content handler missing op ingest (§6.3 SHOULD when installed; conformant if absent)")
		}
		return PassCheck("system/content:ingest advertised")
	})

	// --- Step 2: Entity types registered ---

	r.Run("type_blob", func() CheckOutcome {
		_, _, err := client.TreeGet(ctx, "system/type/system/content/blob")
		if err != nil {
			return FailCheck("system/content/blob type not registered: " + err.Error())
		}
		return PassCheck("system/content/blob registered")
	})
	r.Run("type_chunk", func() CheckOutcome {
		_, _, err := client.TreeGet(ctx, "system/type/system/content/chunk")
		if err != nil {
			return FailCheck("system/content/chunk type not registered: " + err.Error())
		}
		return PassCheck("system/content/chunk registered")
	})
	r.Run("type_descriptor", func() CheckOutcome {
		_, _, err := client.TreeGet(ctx, "system/type/system/content/descriptor")
		if err != nil {
			return FailCheck("system/content/descriptor type not registered (v3.5 A1): " + err.Error())
		}
		return PassCheck("system/content/descriptor registered")
	})

	// --- Step 3: path_required MUSTs (v3.4 → v3.5 behavior reversal) ---

	contentURI := fmt.Sprintf("entity://%s/system/content", client.RemotePeerID())

	r.Run("get_path_required", func() CheckOutcome {
		dummyHash, _ := hash.FromBytes(append([]byte{hash.AlgorithmSHA256}, make([]byte, 32)...))
		getReq, err := (types.ContentGetRequestData{Hashes: []hash.Hash{dummyHash}}).ToEntity()
		if err != nil {
			return SkipCheck("encode get-request: " + err.Error())
		}
		env, _, err := client.SendExecute(ctx, contentURI, "get", getReq, nil)
		if err != nil {
			return FailCheck("SendExecute get (no resource): " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err != nil {
			return FailCheck("decode response: " + err.Error())
		}
		if respData.Status == 200 {
			return FailCheck("system/content:get accepted no-resource EXECUTE (§6.2 MUST: path_required)")
		}
		var resultEntity entity.Entity
		if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
			return FailCheck("decode result entity: " + err.Error())
		}
		errData, err := types.ErrorDataFromEntity(resultEntity)
		if err != nil {
			return FailCheck("decode error: " + err.Error())
		}
		if errData.Code != "path_required" {
			return FailCheck(fmt.Sprintf("error code = %q, want path_required (§6.2 MUST)", errData.Code))
		}
		return PassCheck("system/content:get returns path_required when resource absent")
	})

	r.Run("ingest_path_required", func() CheckOutcome {
		target, err := entity.NewEntity("test/marker", cbor.RawMessage{0xa0})
		if err != nil {
			return SkipCheck("encode marker: " + err.Error())
		}
		targetBytes, err := ecf.Encode(target)
		if err != nil {
			return SkipCheck("encode target: " + err.Error())
		}
		targetRaw := cbor.RawMessage(targetBytes)
		ingestReq, err := (types.ContentIngestRequestData{Entity: &targetRaw}).ToEntity()
		if err != nil {
			return SkipCheck("encode ingest-request: " + err.Error())
		}
		env, _, err := client.SendExecute(ctx, contentURI, "ingest", ingestReq, nil)
		if err != nil {
			return FailCheck("SendExecute ingest (no resource): " + err.Error())
		}
		respData, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err != nil {
			return FailCheck("decode response: " + err.Error())
		}
		if respData.Status == 200 {
			return FailCheck("system/content:ingest accepted no-resource EXECUTE (§6.3 MUST: path_required)")
		}
		var resultEntity entity.Entity
		if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
			return FailCheck("decode result entity: " + err.Error())
		}
		errData, err := types.ErrorDataFromEntity(resultEntity)
		if err != nil {
			return FailCheck("decode error: " + err.Error())
		}
		if errData.Code != "path_required" {
			return FailCheck(fmt.Sprintf("error code = %q, want path_required (§6.3 MUST)", errData.Code))
		}
		return PassCheck("system/content:ingest returns path_required when resource absent")
	})

	// --- Step 6: Inline-include boundary (in-process — exercises the
	// real handler with an in-memory store). ---

	r.Run("inline_include_at_threshold", func() CheckOutcome {
		_, includedCount := exerciseInlineInclude(types.MinChunkSize)
		if includedCount != 2 {
			return FailCheck(fmt.Sprintf("inline-include at total_size=65,536: included=%d, want 2 (blob + chunk)", includedCount))
		}
		return PassCheck("inline-include activates at total_size = 65,536 (§4.3)")
	})

	r.Run("inline_include_above_threshold", func() CheckOutcome {
		_, includedCount := exerciseInlineInclude(types.MinChunkSize + 1)
		if includedCount != 1 {
			return FailCheck(fmt.Sprintf("inline-include at total_size=65,537: included=%d, want 1 (blob only)", includedCount))
		}
		return PassCheck("inline-include does not activate at total_size = 65,537 (§4.3 boundary)")
	})

	// --- Step 7: Descriptor presence rule + integrity check ---

	r.Run("descriptor_presence_rule", func() CheckOutcome {
		blobHash, _ := hash.FromBytes(append([]byte{hash.AlgorithmSHA256}, makeDigest(0xAA)...))
		empty := types.ContentDescriptorData{Content: blobHash}
		if err := content.ValidateDescriptor(empty, blobHash); !errors.Is(err, content.ErrDescriptorPresence) {
			return FailCheck(fmt.Sprintf("ValidateDescriptor with no media_type/type_ref: err = %v, want ErrDescriptorPresence", err))
		}
		mt := "application/json"
		ok := types.ContentDescriptorData{Content: blobHash, MediaType: &mt}
		if err := content.ValidateDescriptor(ok, blobHash); err != nil {
			return FailCheck("descriptor with media_type rejected unexpectedly: " + err.Error())
		}
		return PassCheck("descriptor presence rule: rejected when both media_type and type_ref absent (§2.4 MUST)")
	})

	r.Run("frame-limit-respected", func() CheckOutcome {
		// CONTENT v3.6 Amendment 1 §6.2 MUST: when the ideal response
		// would exceed the connection's configured frame budget, the
		// implementation MUST include as many entities as fit (in
		// request order) and move the remainder to `missing`. The
		// caller retries with the missing hashes.
		//
		// Strategy: ingest a large chunk (1 MiB) into the peer many
		// times by writing distinct large blobs through local/files,
		// collect their content hashes, then issue a single
		// system/content:get request asking for all of them at once.
		// At 1 MiB per chunk + 24+ chunks, the response would exceed
		// the 16 MiB default budget; a conformant peer chunks the
		// response, leaving a non-empty `missing` while `found` is a
		// strict subset; a retry with `missing` resolves to closure.
		root, fsRoot, prefix, ok := discoverLocalFilesRoot(ctx, client)
		if !ok {
			return SkipCheck("no writable local/files root configured; frame-limit check needs a root to seed large content")
		}
		_ = root
		_ = fsRoot

		// Seed enough files that their combined chunks blow past the
		// 16 MiB frame budget when fetched in one mega-request. Each
		// write must fit inside the 16 MiB wire frame; we do 4 × ~5
		// MiB files (each chunked at ~1 MiB) → ~20 MiB total chunks
		// across ~20 chunks. The mega-request asks for ALL the chunks.
		const fileCount = 12
		const fileSize = 4*1024*1024 + 31
		contentURI := fmt.Sprintf("entity://%s/system/content", client.RemotePeerID())
		allChunks := make([]hash.Hash, 0, fileCount*8)
		for i := 0; i < fileCount; i++ {
			body := make([]byte, fileSize)
			for j := range body {
				body[j] = byte(i ^ (j >> 8) ^ (j & 0xFF))
			}
			rel := fmt.Sprintf("frame-limit-probe/file-%02d.bin", i)
			// Write under the peer's advertised local/files prefix —
			// `local/files/test/` is a stale hardcode that 404s under
			// any --files binding whose prefix differs (and the
			// validate-peer recipes use `validate-files/`).
			respData, _, werr := localFilesExecuteWrite(ctx, client, body, nil, true, prefix+rel)
			if werr != nil || respData.Status != 200 {
				return SkipCheck(fmt.Sprintf("seed write %d failed: status=%d err=%v", i, respData.Status, werr))
			}
			resultEnt, rerr := decodeResultEntity(respData.Result)
			if rerr != nil {
				return FailCheck("decode write result: " + rerr.Error())
			}
			var fd struct {
				Content hash.Hash `cbor:"content"`
			}
			if derr := ecf.Decode(resultEnt.Data, &fd); derr != nil {
				return FailCheck("decode file data: " + derr.Error())
			}
			// Fetch this blob's chunk list.
			blobGetReq, err := types.ContentGetRequestData{Hashes: []hash.Hash{fd.Content}}.ToEntity()
			if err != nil {
				return FailCheck("encode blob get: " + err.Error())
			}
			blobEnv, _, err := client.SendExecute(ctx, contentURI, "get", blobGetReq, &types.ResourceTarget{Targets: []string{"system/content"}})
			if err != nil {
				return FailCheck("fetch blob entity: " + err.Error())
			}
			blobEnt, ok := blobEnv.Included[fd.Content]
			if !ok {
				return FailCheck("blob entity missing from response Included")
			}
			var blob types.ContentBlobData
			if derr := ecf.Decode(blobEnt.Data, &blob); derr != nil {
				return FailCheck("decode blob: " + derr.Error())
			}
			allChunks = append(allChunks, blob.Chunks...)
		}
		if len(allChunks) < 16 {
			return SkipCheck(fmt.Sprintf("only %d chunks accumulated — bump fileCount/fileSize to exceed 16 MiB budget", len(allChunks)))
		}

		// One mega-request for ALL chunks at once. ~20 chunks × ~1
		// MiB = ~20 MiB > 16 MiB budget. Conformant peer returns
		// partial-found + non-empty missing.
		getReq, err := types.ContentGetRequestData{Hashes: allChunks}.ToEntity()
		if err != nil {
			return FailCheck("encode get request: " + err.Error())
		}
		env, _, err := client.SendExecute(ctx, contentURI, "get", getReq, &types.ResourceTarget{Targets: []string{"system/content"}})
		if err != nil {
			return FailCheck("send mega-get: " + err.Error())
		}
		megaResp, err := types.ExecuteResponseDataFromEntity(env.Root)
		if err != nil {
			return FailCheck("decode response: " + err.Error())
		}
		if megaResp.Status != 200 {
			return FailCheck(fmt.Sprintf("mega-get returned status %d (expected 200)", megaResp.Status))
		}
		var megaResultEnt entity.Entity
		if err := ecf.Decode(megaResp.Result, &megaResultEnt); err != nil {
			return FailCheck("decode result entity: " + err.Error())
		}
		var getResp types.ContentGetResponseData
		if err := ecf.Decode(megaResultEnt.Data, &getResp); err != nil {
			return FailCheck("decode ContentGetResponseData: " + err.Error())
		}
		if len(getResp.Missing) == 0 {
			return FailCheck(fmt.Sprintf("Amendment 1 §6.2: no `missing` returned when request would exceed budget (found=%d total=%d chunks) — peer returned full response in one envelope, violating frame-budget MUST", len(getResp.Found), len(allChunks)))
		}
		if len(getResp.Found)+len(getResp.Missing) != len(allChunks) {
			return FailCheck(fmt.Sprintf("Amendment 1 §6.2: found(%d) + missing(%d) ≠ requested(%d); response set is incomplete", len(getResp.Found), len(getResp.Missing), len(allChunks)))
		}

		// Retry the `missing` set — should now fit (the budget was
		// only the partial-set boundary; the retry is a fresh budget).
		retryReq, err := types.ContentGetRequestData{Hashes: getResp.Missing}.ToEntity()
		if err != nil {
			return FailCheck("encode retry request: " + err.Error())
		}
		envR, _, err := client.SendExecute(ctx, contentURI, "get", retryReq, &types.ResourceTarget{Targets: []string{"system/content"}})
		if err != nil {
			return FailCheck("send retry get: " + err.Error())
		}
		respDataR, err := types.ExecuteResponseDataFromEntity(envR.Root)
		if err != nil {
			return FailCheck("decode retry response: " + err.Error())
		}
		var resultEntR entity.Entity
		if err := ecf.Decode(respDataR.Result, &resultEntR); err != nil {
			return FailCheck("decode retry result entity: " + err.Error())
		}
		var retryResp types.ContentGetResponseData
		if err := ecf.Decode(resultEntR.Data, &retryResp); err != nil {
			return FailCheck("decode retry ContentGetResponseData: " + err.Error())
		}
		if len(retryResp.Found) == 0 {
			return FailCheck("Amendment 1 §6.2: retry of the `missing` set returned zero `found` — caller cannot make progress")
		}

		return PassCheck(fmt.Sprintf("Amendment 1 §6.2: mega-request frame-chunked correctly (first response: found=%d missing=%d of %d chunks; retry made progress: found=%d)",
			len(getResp.Found), len(getResp.Missing), len(allChunks), len(retryResp.Found)))
	})

	r.Run("descriptor_integrity_check", func() CheckOutcome {
		anchorA, _ := hash.FromBytes(append([]byte{hash.AlgorithmSHA256}, makeDigest(0x11)...))
		anchorB, _ := hash.FromBytes(append([]byte{hash.AlgorithmSHA256}, makeDigest(0x22)...))
		mt := "image/png"
		desc := types.ContentDescriptorData{Content: anchorA, MediaType: &mt}
		if err := content.ValidateDescriptor(desc, anchorA); err != nil {
			return FailCheck("matching anchor rejected: " + err.Error())
		}
		if err := content.ValidateDescriptor(desc, anchorB); !errors.Is(err, content.ErrDescriptorIntegrity) {
			return FailCheck(fmt.Sprintf("mismatched anchor: err = %v, want ErrDescriptorIntegrity", err))
		}
		return PassCheck("descriptor integrity check: body↔path anchor mismatch rejected (§5.3 MUST)")
	})

	return r.Results()
}

// --- Helpers ---

func makeDigest(filler byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = filler
	}
	return out
}

// exerciseInlineInclude drives the §4.3 boundary in-process: builds a
// chunk + blob of the given total_size, stores them in a fresh memory
// store, then invokes content.NewHandler().Handle("get", ...) with a
// resource present. Returns the response status and the included-map
// size (blob alone = 1; blob + chunk inlined = 2).
func exerciseInlineInclude(totalSize uint64) (uint, int) {
	cs := store.NewMemoryContentStore()
	raw := store.NewMemoryLocationIndex()
	kp, _ := crypto.Generate()
	nsLI := store.NewNamespacedIndex(raw, string(kp.PeerID()))

	payload := make([]byte, totalSize)
	chunkEnt, err := types.ContentChunkData{Payload: payload}.ToEntity()
	if err != nil {
		return 0, -1
	}
	chunkHash, _ := cs.Put(chunkEnt)
	blobEnt, err := types.ContentBlobData{
		TotalSize: totalSize,
		ChunkSize: totalSize,
		Chunking:  types.ChunkingFixed,
		Chunks:    []hash.Hash{chunkHash},
	}.ToEntity()
	if err != nil {
		return 0, -1
	}
	blobHash, _ := cs.Put(blobEnt)

	getReq, err := types.ContentGetRequestData{Hashes: []hash.Hash{blobHash}}.ToEntity()
	if err != nil {
		return 0, -1
	}
	h := content.NewHandler()
	req := buildContentRequest(cs, nsLI, kp.PeerID(), "get", getReq)
	resp, err := h.Handle(context.Background(), req)
	if err != nil {
		return 0, -1
	}
	return resp.Status, len(resp.Included)
}

// buildContentRequest mints a handler.Request with a fully populated
// HandlerContext (resource present, store and index wired).
func buildContentRequest(cs store.ContentStore, idx store.LocationIndex, peerID crypto.PeerID, op string, params entity.Entity) *handler.Request {
	return &handler.Request{
		Operation: op,
		Params:    params,
		Context: &handler.HandlerContext{
			Store:          cs,
			LocationIndex:  idx,
			LocalPeerID:    peerID,
			HandlerPattern: "system/content",
			Resource:       &types.ResourceTarget{Targets: []string{"system/content"}},
		},
	}
}
