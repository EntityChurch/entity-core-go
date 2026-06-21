package validate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/content"
	"go.entitychurch.org/entity-core-go/ext/content/chunker"
	"go.entitychurch.org/entity-core-go/ext/localfiles"

	"github.com/fxamacker/cbor/v2"
)

const catLocalFiles = "local_files"

// runLocalFiles validates the local/files domain handler (v1.2 on
// CONTENT v3.6) against a remote peer. The category exercises:
//
//   - Handler manifest + per-operation registration (§3.1)
//   - Type registration in the tree (§10)
//   - read / write / list / delete round-trips
//   - v1.2 file-entity shape: Content as system/hash; no encoding sidecar
//   - CONTENT v3.6 §4.3 inline-include boundary on read (64 KiB)
//   - Cross-handler dedup: a locally-built blob hash equals what a
//     local/files:read produces for the same bytes (Go-impl tests the
//     intra-impl convergence; against a sibling peer, this becomes the
//     cross-impl gate)
//   - Edit stability: a 1-byte mid-file edit reuses almost all chunks
//   - Content-mode write (dedup): write by blob-hash reference
func runLocalFiles(ctx context.Context, client *PeerClient) []CheckResult {
	r := NewCheckRunner(catLocalFiles)

	// Discover a WRITABLE local/files root the target actually advertises,
	// over the wire, and run the read/write/list/delete round-trip against
	// THAT root's real tree prefix — instead of assuming a hardcoded
	// `local/files/test/` mount. Two predictability wins:
	//   - When the peer has no writable root (the common case — most runs
	//     aren't testing files), the round-trip is reported as a single clean
	//     WARN, not a wall of 404 FAILs that read like a conformance
	//     divergence. WARN (not SKIP) because SKIP counts toward the failed
	//     bucket; absent-mount is conformant, so it must not look like a fail.
	//   - When a root IS mounted, the prefix is taken from the peer's own
	//     root-config, so any mount name works — no more "mounted at docs/ but
	//     the suite hardcoded test/" mismatch.
	// The on-disk behavioral gates (V2-V4) keep their own fs-aware discovery.
	roundTripBase, roundTripRootOK := discoverWritableLocalFilesPrefix(ctx, client)

	// --- Declarations ---

	r.Declare("handler_manifest_present", "LOCAL-FILES §3.1")
	r.Declare("handler_manifest_decode", "LOCAL-FILES §3.1")
	r.Declare("handler_op_read", "LOCAL-FILES §3.1")
	r.Declare("handler_op_write", "LOCAL-FILES §3.1")
	r.Declare("handler_op_list", "LOCAL-FILES §3.1")
	r.Declare("handler_op_delete", "LOCAL-FILES §3.1")
	r.Declare("handler_op_watch", "LOCAL-FILES §3.1")

	r.Declare("type_file", "LOCAL-FILES §10")
	r.Declare("type_directory", "LOCAL-FILES §10")
	r.Declare("type_directory_entry", "LOCAL-FILES §10")
	r.Declare("type_deleted", "LOCAL-FILES §10")
	r.Declare("type_root_config", "LOCAL-FILES §10")
	r.Declare("type_watcher_config", "LOCAL-FILES §10")
	r.Declare("type_write_request", "LOCAL-FILES §10")
	r.Declare("type_watch_request", "LOCAL-FILES §10")

	r.Declare("root_config_present", "LOCAL-FILES §2.6")

	if roundTripRootOK {
		r.Declare("read_setup_write", "LOCAL-FILES v1.3 §5.4")
		r.Declare("read_status_200", "LOCAL-FILES v1.3 §5.3")
		r.Declare("read_result_type", "LOCAL-FILES v1.3 §5.1")
		r.Declare("read_content_hash", "LOCAL-FILES v1.3 §5.1")
		r.Declare("read_blob_in_included", "CONTENT v3.6 §4.3")
		r.Declare("read_chunks_in_included_small", "CONTENT v3.6 §4.3")

		r.Declare("write_status_200", "LOCAL-FILES v1.3 §5.4")
		r.Declare("write_written_flag", "LOCAL-FILES v1.3 §5.4")
		r.Declare("write_read_back_blob_hash", "LOCAL-FILES v1.3 §5.4")
		r.Declare("write_content_mode_dedup", "LOCAL-FILES v1.3 §5.4")
		r.Declare("write_blob_in_included", "LOCAL-FILES v1.3 §10.1 MUST")
		r.Declare("write_chunks_in_included_small", "LOCAL-FILES v1.3 §10.1 MUST")
		r.Declare("write_inline_include_above_boundary", "LOCAL-FILES v1.3 §10.1 MUST")
		r.Declare("write_rejects_neither_set", "LOCAL-FILES v1.3 §3.2 presence rule")
		r.Declare("write_rejects_both_set", "LOCAL-FILES v1.3 §3.2 presence rule")
		r.Declare("write_content_mode_unknown_blob", "LOCAL-FILES v1.3 §4.3")
		r.Declare("write_empty_file", "CONTENT v3.6 §3.6 boundary case")

		r.Declare("list_status_200", "LOCAL-FILES §4.2")
		r.Declare("list_result_type", "LOCAL-FILES §4.2")
		r.Declare("list_has_children", "LOCAL-FILES §4.2")

		r.Declare("delete_status_200", "LOCAL-FILES §4.4")
		r.Declare("delete_result_type", "LOCAL-FILES §4.4")
		r.Declare("delete_confirmed", "LOCAL-FILES §4.4")

		r.Declare("content_dedup_same_blob_hash", "LOCAL-FILES v1.3 §5.1")
		r.Declare("cross_handler_dedup_blob_hash", "CONTENT v3.6 §3.7")
		r.Declare("inline_include_boundary_below", "CONTENT v3.6 §4.3")
		r.Declare("inline_include_boundary_above", "CONTENT v3.6 §4.3")
		r.Declare("edit_stability_chunk_reuse", "CONTENT v3.6 §3.6")
	} else {
		r.Declare("local_files_roundtrip_available", "LOCAL-FILES v1.3 §2.6")
	}

	// v1.3 behavioral gates (Phase 4-bis per spec §10.5):
	r.Declare("v1_oversized_bytes_mode_graceful", "DOMAIN-LOCAL-FILES v1.3 §10.5 V1")
	r.Declare("v2_watcher_fires_on_disk_edit", "DOMAIN-LOCAL-FILES v1.3 §10.5 V2 + §10.1 MUST-iff-declared")
	r.Declare("v3_descriptor_publish_exercised", "DOMAIN-LOCAL-FILES v1.3 §10.5 V3")
	r.Declare("v4_leaf_symlink_rejected", "DOMAIN-LOCAL-FILES v1.3 §10.5 V4 + §8.3 MUST + §865 error-code pin")

	// --- Step 1: Handler manifest ---

	r.Run("handler_manifest_present", func() CheckOutcome {
		ent, _, err := client.TreeGet(ctx, "system/handler/local/files")
		if err != nil {
			return FailCheck("failed to fetch local/files handler manifest: " + err.Error())
		}
		r.Store("manifest_entity", ent)
		return PassCheck(fmt.Sprintf("local/files handler manifest present (type: %s)", ent.Type))
	})

	r.Run("handler_manifest_decode", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest_present"); !ok {
			return out
		}
		ent := r.Load("manifest_entity").(entity.Entity)
		handlerData, err := types.HandlerInterfaceDataFromEntity(ent)
		if err != nil {
			return FailCheck("could not decode handler manifest: " + err.Error())
		}
		r.Store("handler_data", handlerData)
		return PassCheck("handler manifest decoded successfully")
	})

	for _, op := range []string{"read", "write", "list", "delete"} {
		op := op
		r.Run("handler_op_"+op, func() CheckOutcome {
			if out, ok := r.Require("handler_manifest_decode"); !ok {
				return out
			}
			handlerData := r.Load("handler_data").(types.HandlerInterfaceData)
			if _, exists := handlerData.Operations[op]; !exists {
				return FailCheck("local/files handler missing operation: " + op)
			}
			return PassCheck("local/files handler has operation: " + op)
		})
	}

	// watch is MUST-iff-declared per v1.3 §10.1 L2 — impls without a
	// working watcher MUST omit it from the manifest rather than ship a
	// silently-non-functional handler. Mirror the V2 behavioral check's
	// skip-with-WARN pattern: absent = conformant interim per L2; present
	// = handler must actually support it (V2 exercises this on disk).
	// Per Python's B-1 pushback.
	r.Run("handler_op_watch", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest_decode"); !ok {
			return out
		}
		handlerData := r.Load("handler_data").(types.HandlerInterfaceData)
		if _, exists := handlerData.Operations["watch"]; !exists {
			return WarnCheck("watch not in manifest — per v1.3 §10.1 L2 MUST-iff-declared this is conformant; behavioral V2 also skips with WARN")
		}
		return PassCheck("local/files handler has operation: watch")
	})

	// --- Step 2: Type registration ---

	typeChecks := []struct{ name, path string }{
		{"file", "system/type/local/files/file"},
		{"directory", "system/type/local/files/directory"},
		{"directory_entry", "system/type/local/files/directory/entry"},
		{"deleted", "system/type/local/files/deleted"},
		{"root_config", "system/type/local/files/root-config"},
		{"watcher_config", "system/type/local/files/watcher-config"},
		{"write_request", "system/type/local/files/write-request"},
		{"watch_request", "system/type/local/files/watch-request"},
	}
	for _, tc := range typeChecks {
		tc := tc
		r.Run("type_"+tc.name, func() CheckOutcome {
			_, _, err := client.TreeGet(ctx, tc.path)
			if err != nil {
				return FailCheck("type not registered: " + tc.path)
			}
			return PassCheck("type registered: " + tc.path)
		})
	}

	// --- Step 3: Root config presence ---

	r.Run("root_config_present", func() CheckOutcome {
		entries, _, err := client.TreeListing(ctx, "system/config/local/files/")
		if err != nil || len(entries) == 0 {
			return WarnCheck("no root config entities found at system/config/local/files/")
		}
		return PassCheck(fmt.Sprintf("found %d root config(s) at system/config/local/files/", len(entries)))
	})

	// --- Step 4: Read round-trip ---

	if roundTripRootOK {
		const readBody = "validation read test content"
		r.Run("read_setup_write", func() CheckOutcome {
			_, _, err := localFilesExecuteWrite(ctx, client, []byte(readBody), nil, true, roundTripBase+"validate-read.txt")
			if err != nil {
				return FailCheck("setup write failed: " + err.Error())
			}
			return PassCheck("setup write for read test succeeded")
		})

		r.Run("read_status_200", func() CheckOutcome {
			if out, ok := r.Require("read_setup_write"); !ok {
				return out
			}
			respData, env, err := localFilesExecuteSimple(ctx, client, "read", roundTripBase+"validate-read.txt")
			if err != nil {
				return FailCheck("read failed: " + err.Error())
			}
			if respData.Status != 200 {
				return FailCheck(fmt.Sprintf("read returned status %d", respData.Status))
			}
			r.Store("read_resp", respData)
			r.Store("read_env", env)
			return PassCheck("read operation returned 200")
		})

		r.Run("read_result_type", func() CheckOutcome {
			if out, ok := r.Require("read_status_200"); !ok {
				return out
			}
			respData := r.Load("read_resp").(types.ExecuteResponseData)
			resultEnt, err := decodeResultEntity(respData.Result)
			if err != nil {
				return FailCheck("decode result entity: " + err.Error())
			}
			if resultEnt.Type != localfiles.TypeFile {
				return FailCheck(fmt.Sprintf("expected %s, got %s", localfiles.TypeFile, resultEnt.Type))
			}
			r.Store("read_result_entity", resultEnt)
			return PassCheck("read result type is local/files/file")
		})

		r.Run("read_content_hash", func() CheckOutcome {
			if out, ok := r.Require("read_result_type"); !ok {
				return out
			}
			resultEnt := r.Load("read_result_entity").(entity.Entity)
			var fileData localfiles.FileData
			if err := ecf.Decode(resultEnt.Data, &fileData); err != nil {
				return FailCheck("decode file data: " + err.Error())
			}
			if fileData.Content.IsZero() {
				return FailCheck("v1.2 file entity must carry a non-zero content blob hash")
			}
			r.Store("read_file_data", fileData)
			return PassCheck("read returned a non-zero content blob hash")
		})

		r.Run("read_blob_in_included", func() CheckOutcome {
			if out, ok := r.Require("read_content_hash"); !ok {
				return out
			}
			fileData := r.Load("read_file_data").(localfiles.FileData)
			env := r.Load("read_env").(entity.Envelope)
			if _, ok := env.Included[fileData.Content]; !ok {
				return FailCheck("§4.3: blob entity should be present in response Included")
			}
			return PassCheck("blob entity present in response Included")
		})

		r.Run("read_chunks_in_included_small", func() CheckOutcome {
			if out, ok := r.Require("read_blob_in_included"); !ok {
				return out
			}
			fileData := r.Load("read_file_data").(localfiles.FileData)
			env := r.Load("read_env").(entity.Envelope)
			blob, err := decodeBlob(env.Included[fileData.Content])
			if err != nil {
				return FailCheck("decode blob from Included: " + err.Error())
			}
			if blob.TotalSize > types.MinChunkSize {
				return SkipCheck("read body exceeds MIN_CHUNK_SIZE; small-file inline path not exercised")
			}
			for _, ch := range blob.Chunks {
				if _, ok := env.Included[ch]; !ok {
					return FailCheck(fmt.Sprintf("§4.3: chunk %x missing from Included for small file", ch.Digest[:8]))
				}
			}
			return PassCheck(fmt.Sprintf("§4.3: all %d chunks present in Included for size %d ≤ MIN_CHUNK_SIZE", len(blob.Chunks), blob.TotalSize))
		})

		// --- Step 5: Write round-trip ---

		const writeBody = "write validation round-trip"
		var writeBlobHash hash.Hash
		r.Run("write_status_200", func() CheckOutcome {
			respData, _, err := localFilesExecuteWrite(ctx, client, []byte(writeBody), nil, false, roundTripBase+"validate-write.txt")
			if err != nil {
				return FailCheck("write failed: " + err.Error())
			}
			if respData.Status != 200 {
				return FailCheck(fmt.Sprintf("write returned status %d", respData.Status))
			}
			r.Store("write_resp", respData)
			return PassCheck("write operation returned 200")
		})

		r.Run("write_written_flag", func() CheckOutcome {
			if out, ok := r.Require("write_status_200"); !ok {
				return out
			}
			resp := r.Load("write_resp").(types.ExecuteResponseData)
			resultEnt, _ := decodeResultEntity(resp.Result)
			var fileData localfiles.FileData
			if err := ecf.Decode(resultEnt.Data, &fileData); err != nil {
				return FailCheck("decode write file data: " + err.Error())
			}
			if !fileData.Written {
				return FailCheck("write response missing written=true")
			}
			writeBlobHash = fileData.Content
			return PassCheck("write response has written=true")
		})

		r.Run("write_read_back_blob_hash", func() CheckOutcome {
			if out, ok := r.Require("write_written_flag"); !ok {
				return out
			}
			respData, _, err := localFilesExecuteSimple(ctx, client, "read", roundTripBase+"validate-write.txt")
			if err != nil || respData.Status != 200 {
				return FailCheck("read-back failed")
			}
			ent, _ := decodeResultEntity(respData.Result)
			var fd localfiles.FileData
			if err := ecf.Decode(ent.Data, &fd); err != nil {
				return FailCheck("decode read-back: " + err.Error())
			}
			if fd.Content != writeBlobHash {
				return FailCheck(fmt.Sprintf("read-back blob hash differs from write: %v vs %v", fd.Content, writeBlobHash))
			}
			return PassCheck("write→read round-trip preserves blob hash")
		})

		// Write-side inline-include: DOMAIN-LOCAL-FILES v1.3 §10.1 promotes
		// CONTENT v3.6 §4.3 SHOULD → MUST at the local/files surface for BOTH
		// read and write. Read-side checks above; these three close the write
		// half of the surface.
		r.Run("write_blob_in_included", func() CheckOutcome {
			respData, env, err := localFilesExecuteWrite(ctx, client, []byte("write inline-include blob test"), nil, true, roundTripBase+"validate-write-inline.txt")
			if err != nil || respData.Status != 200 {
				return FailCheck("write failed: " + fmt.Sprintf("status=%d err=%v", respData.Status, err))
			}
			ent, _ := decodeResultEntity(respData.Result)
			var fd localfiles.FileData
			if err := ecf.Decode(ent.Data, &fd); err != nil {
				return FailCheck("decode file data: " + err.Error())
			}
			if _, ok := env.Included[fd.Content]; !ok {
				return FailCheck("§10.1 MUST: write response Included is missing the blob entity")
			}
			return PassCheck("write response Included contains the blob entity")
		})

		r.Run("write_chunks_in_included_small", func() CheckOutcome {
			body := bytes.Repeat([]byte{'W'}, int(types.MinChunkSize))
			respData, env, err := localFilesExecuteWrite(ctx, client, body, nil, true, roundTripBase+"validate-write-small.bin")
			if err != nil || respData.Status != 200 {
				return FailCheck("write failed")
			}
			ent, _ := decodeResultEntity(respData.Result)
			var fd localfiles.FileData
			if err := ecf.Decode(ent.Data, &fd); err != nil {
				return FailCheck("decode file data: " + err.Error())
			}
			blobEnt, ok := env.Included[fd.Content]
			if !ok {
				return FailCheck("blob entity missing from write response Included at MIN_CHUNK_SIZE")
			}
			blob, err := decodeBlob(blobEnt)
			if err != nil {
				return FailCheck("decode blob: " + err.Error())
			}
			for _, ch := range blob.Chunks {
				if _, ok := env.Included[ch]; !ok {
					return FailCheck(fmt.Sprintf("§10.1 MUST: chunk %x missing from write response Included at total_size = MIN_CHUNK_SIZE", ch.Digest[:8]))
				}
			}
			return PassCheck(fmt.Sprintf("§10.1 MUST: write response includes all %d chunks at total_size = MIN_CHUNK_SIZE", len(blob.Chunks)))
		})

		r.Run("write_inline_include_above_boundary", func() CheckOutcome {
			body := bytes.Repeat([]byte{'X'}, int(types.MinChunkSize)+1)
			respData, env, err := localFilesExecuteWrite(ctx, client, body, nil, true, roundTripBase+"validate-write-large.bin")
			if err != nil || respData.Status != 200 {
				return FailCheck("write failed")
			}
			ent, _ := decodeResultEntity(respData.Result)
			var fd localfiles.FileData
			if err := ecf.Decode(ent.Data, &fd); err != nil {
				return FailCheck("decode file data: " + err.Error())
			}
			blobEnt, ok := env.Included[fd.Content]
			if !ok {
				return FailCheck("blob entity must remain in Included above the threshold (CONTENT §5.2 MUST)")
			}
			blob, err := decodeBlob(blobEnt)
			if err != nil {
				return FailCheck("decode blob: " + err.Error())
			}
			for _, ch := range blob.Chunks {
				if _, ok := env.Included[ch]; ok {
					return FailCheck(fmt.Sprintf("§10.1: chunk %x should NOT be in write Included above MIN_CHUNK_SIZE", ch.Digest[:8]))
				}
			}
			return PassCheck(fmt.Sprintf("§10.1: write of size = MIN_CHUNK_SIZE+1 (%d) → blob included; chunks not inlined", types.MinChunkSize+1))
		})

		// Edge cases — divergence-prone spots where impls are most likely to
		// differ. Each check pins a spec-defined behavior that's easy to
		// implement wrong if not specifically tested.

		r.Run("write_rejects_neither_set", func() CheckOutcome {
			// Spec §3.2: neither-set ⇒ 400 invalid_params "missing_input".
			d := localfiles.WriteRequestData{CreateDirs: true}
			raw, _ := ecf.Encode(d)
			paramsEnt, _ := entity.NewEntity(localfiles.TypeWriteRequest, cbor.RawMessage(raw))
			uri := fmt.Sprintf("entity://%s/local/files", client.RemotePeerID())
			env, _, err := client.SendExecute(ctx, uri, "write", paramsEnt, &types.ResourceTarget{Targets: []string{roundTripBase + "edge-neither.txt"}})
			if err != nil {
				return FailCheck("wire error: " + err.Error())
			}
			respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
			if respData.Status != 400 {
				return FailCheck(fmt.Sprintf("§3.2: neither-set should return 400, got %d", respData.Status))
			}
			return PassCheck("§3.2: neither bytes nor content set → 400 as required")
		})

		r.Run("write_rejects_both_set", func() CheckOutcome {
			// Spec §3.2: both-set ⇒ 400 invalid_params "ambiguous_input".
			// Use a real blob hash to make the request well-formed except for
			// the both-set violation (avoids ambiguity with "unknown blob").
			realHash := localBuildBlobHash([]byte("for both-set test"))
			d := localfiles.WriteRequestData{Bytes: []byte("conflicting"), Content: &realHash, CreateDirs: true}
			raw, _ := ecf.Encode(d)
			paramsEnt, _ := entity.NewEntity(localfiles.TypeWriteRequest, cbor.RawMessage(raw))
			uri := fmt.Sprintf("entity://%s/local/files", client.RemotePeerID())
			env, _, err := client.SendExecute(ctx, uri, "write", paramsEnt, &types.ResourceTarget{Targets: []string{roundTripBase + "edge-both.txt"}})
			if err != nil {
				return FailCheck("wire error: " + err.Error())
			}
			respData, _ := types.ExecuteResponseDataFromEntity(env.Root)
			if respData.Status != 400 {
				return FailCheck(fmt.Sprintf("§3.2: both-set should return 400, got %d", respData.Status))
			}
			return PassCheck("§3.2: both bytes and content set → 400 as required")
		})

		r.Run("write_content_mode_unknown_blob", func() CheckOutcome {
			// Spec §4.3 content-mode: blob not in store ⇒ 404 content_not_found.
			// Use a hash that's deterministically not present (a unique tag we
			// just generated and never ingested).
			unknownHash := localBuildBlobHash([]byte("edge-unknown-blob-tag-never-written-here"))
			respData, _, err := localFilesExecuteWrite(ctx, client, nil, &unknownHash, true, roundTripBase+"edge-unknown.txt")
			if err != nil {
				return FailCheck("wire error: " + err.Error())
			}
			if respData.Status != 404 {
				return FailCheck(fmt.Sprintf("§4.3: content-mode with unknown blob should return 404, got %d", respData.Status))
			}
			return PassCheck("§4.3: content-mode with unknown blob → 404 as required")
		})

		r.Run("write_empty_file", func() CheckOutcome {
			// Bytes-mode write with 0-length payload. The chunker may produce
			// 0 chunks; the blob has total_size 0. Read-back must reassemble
			// to empty bytes and the disk file must be 0 bytes.
			respData, env, err := localFilesExecuteWrite(ctx, client, []byte{}, nil, true, roundTripBase+"edge-empty.txt")
			if err != nil {
				return FailCheck("wire error: " + err.Error())
			}
			// Some impls may reject empty bytes via the presence-rule check
			// (len(bytes) > 0 vs bytes != nil). Either spec interpretation —
			// 200 (empty file is a real file) or 400 (presence-rule treats
			// empty bytes as not-set) — is internally consistent; we accept
			// both and surface which one the impl chose.
			if respData.Status == 400 {
				return PassCheck("§3.2: empty bytes treated as not-set → 400 (one valid spec reading)")
			}
			if respData.Status != 200 {
				return FailCheck(fmt.Sprintf("empty write returned unexpected status %d", respData.Status))
			}
			ent, _ := decodeResultEntity(respData.Result)
			var fd localfiles.FileData
			if err := ecf.Decode(ent.Data, &fd); err != nil {
				return FailCheck("decode file data: " + err.Error())
			}
			if fd.Size != 0 {
				return FailCheck(fmt.Sprintf("empty write: file entity size = %d (expected 0)", fd.Size))
			}
			blobEnt, ok := env.Included[fd.Content]
			if !ok {
				return FailCheck("empty write: blob not in Included")
			}
			blob, err := decodeBlob(blobEnt)
			if err != nil {
				return FailCheck("decode blob: " + err.Error())
			}
			if blob.TotalSize != 0 {
				return FailCheck(fmt.Sprintf("empty write: blob total_size = %d (expected 0)", blob.TotalSize))
			}
			return PassCheck(fmt.Sprintf("empty write succeeded — file size 0, blob total_size 0, chunks=%d", len(blob.Chunks)))
		})

		r.Run("write_content_mode_dedup", func() CheckOutcome {
			if out, ok := r.Require("write_written_flag"); !ok {
				return out
			}
			// Reuse the blob from the previous write — content-mode write
			// projects the same bytes to a new path via hash reference, no
			// re-transmit of the payload.
			respData, _, err := localFilesExecuteWrite(ctx, client, nil, &writeBlobHash, false, roundTripBase+"validate-dedup.txt")
			if err != nil {
				return FailCheck("content-mode write failed: " + err.Error())
			}
			if respData.Status != 200 {
				return FailCheck(fmt.Sprintf("content-mode write returned status %d", respData.Status))
			}
			ent, _ := decodeResultEntity(respData.Result)
			var fd localfiles.FileData
			if err := ecf.Decode(ent.Data, &fd); err != nil {
				return FailCheck("decode dedup file data: " + err.Error())
			}
			if fd.Content != writeBlobHash {
				return FailCheck("content-mode write should preserve input blob hash")
			}
			return PassCheck("content-mode write succeeded and preserved input blob hash")
		})

		// --- Step 6: List ---

		r.Run("list_status_200", func() CheckOutcome {
			respData, _, err := localFilesExecuteSimple(ctx, client, "list", roundTripBase)
			if err != nil {
				return FailCheck("list failed: " + err.Error())
			}
			if respData.Status != 200 {
				return FailCheck(fmt.Sprintf("list returned status %d", respData.Status))
			}
			r.Store("list_resp", respData)
			return PassCheck("list operation returned 200")
		})

		r.Run("list_result_type", func() CheckOutcome {
			if out, ok := r.Require("list_status_200"); !ok {
				return out
			}
			resp := r.Load("list_resp").(types.ExecuteResponseData)
			resultEnt, _ := decodeResultEntity(resp.Result)
			if resultEnt.Type != localfiles.TypeDirectory {
				return FailCheck(fmt.Sprintf("expected %s, got %s", localfiles.TypeDirectory, resultEnt.Type))
			}
			r.Store("list_result_entity", resultEnt)
			return PassCheck("list result type is local/files/directory")
		})

		r.Run("list_has_children", func() CheckOutcome {
			if out, ok := r.Require("list_result_type"); !ok {
				return out
			}
			resultEnt := r.Load("list_result_entity").(entity.Entity)
			var dirData localfiles.DirectoryData
			if err := ecf.Decode(resultEnt.Data, &dirData); err == nil && len(dirData.Children) > 0 {
				return PassCheck(fmt.Sprintf("directory listing has %d entries", len(dirData.Children)))
			}
			return WarnCheck("directory listing has no children")
		})

		// --- Step 7: Delete ---

		r.Run("delete_status_200", func() CheckOutcome {
			_, _, _ = localFilesExecuteWrite(ctx, client, []byte("to be deleted"), nil, true, roundTripBase+"validate-delete.txt")
			respData, _, err := localFilesExecuteSimple(ctx, client, "delete", roundTripBase+"validate-delete.txt")
			if err != nil {
				return FailCheck("delete failed: " + err.Error())
			}
			if respData.Status != 200 {
				return FailCheck(fmt.Sprintf("delete returned status %d", respData.Status))
			}
			r.Store("delete_resp", respData)
			return PassCheck("delete operation returned 200")
		})

		r.Run("delete_result_type", func() CheckOutcome {
			if out, ok := r.Require("delete_status_200"); !ok {
				return out
			}
			resp := r.Load("delete_resp").(types.ExecuteResponseData)
			resultEnt, _ := decodeResultEntity(resp.Result)
			if resultEnt.Type != localfiles.TypeDeleted {
				return FailCheck(fmt.Sprintf("expected %s, got %s", localfiles.TypeDeleted, resultEnt.Type))
			}
			return PassCheck("delete result type is local/files/deleted")
		})

		r.Run("delete_confirmed", func() CheckOutcome {
			if out, ok := r.Require("delete_status_200"); !ok {
				return out
			}
			respData, _, err := localFilesExecuteSimple(ctx, client, "read", roundTripBase+"validate-delete.txt")
			if err == nil && respData.Status == 404 {
				return PassCheck("file returns 404 after delete")
			}
			return WarnCheck("file may not be fully removed after delete")
		})

		// --- Step 8: Dedup + cross-handler convergence ---

		const dedupBody = "dedup validation content"
		r.Run("content_dedup_same_blob_hash", func() CheckOutcome {
			_, _, _ = localFilesExecuteWrite(ctx, client, []byte(dedupBody), nil, true, roundTripBase+"dedup-a.txt")
			_, _, _ = localFilesExecuteWrite(ctx, client, []byte(dedupBody), nil, true, roundTripBase+"dedup-b.txt")

			respA, _, errA := localFilesExecuteSimple(ctx, client, "read", roundTripBase+"dedup-a.txt")
			respB, _, errB := localFilesExecuteSimple(ctx, client, "read", roundTripBase+"dedup-b.txt")
			if errA != nil || errB != nil || respA.Status != 200 || respB.Status != 200 {
				return SkipCheck("could not read both dedup test files")
			}

			entA, _ := decodeResultEntity(respA.Result)
			entB, _ := decodeResultEntity(respB.Result)
			var fdA, fdB localfiles.FileData
			ecf.Decode(entA.Data, &fdA)
			ecf.Decode(entB.Data, &fdB)

			if fdA.Content.IsZero() || fdB.Content.IsZero() {
				return SkipCheck("content blob hash not populated")
			}
			if fdA.Content == fdB.Content {
				return PassCheck("identical content produces same blob hash (dedup works)")
			}
			return FailCheck("identical content produced different blob hashes")
		})

		r.Run("cross_handler_dedup_blob_hash", func() CheckOutcome {
			if out, ok := r.Require("content_dedup_same_blob_hash"); !ok {
				return out
			}
			// Build the same blob locally via the same shared substrate. A
			// conformant peer's local/files:read must produce the byte-identical
			// blob hash. Tests intra-impl convergence; against a sibling peer,
			// this becomes the CONTENT §3.7 cross-impl gate.
			respData, _, err := localFilesExecuteSimple(ctx, client, "read", roundTripBase+"dedup-a.txt")
			if err != nil || respData.Status != 200 {
				return SkipCheck("read failed")
			}
			ent, _ := decodeResultEntity(respData.Result)
			var fd localfiles.FileData
			if err := ecf.Decode(ent.Data, &fd); err != nil {
				return FailCheck("decode file data: " + err.Error())
			}

			expected := localBuildBlobHash([]byte(dedupBody))
			if fd.Content != expected {
				return FailCheck(fmt.Sprintf("local/files:read blob hash %x diverges from local-built %x", fd.Content.Digest[:8], expected.Digest[:8]))
			}
			return PassCheck("local/files:read converges with ext/content substrate on blob hash")
		})

		// --- Step 9: Inline-include boundary at 64 KiB ---

		r.Run("inline_include_boundary_below", func() CheckOutcome {
			body := bytes.Repeat([]byte{'A'}, int(types.MinChunkSize))
			_, _, err := localFilesExecuteWrite(ctx, client, body, nil, true, roundTripBase+"inline-64k.bin")
			if err != nil {
				return FailCheck("setup write failed: " + err.Error())
			}
			respData, env, err := localFilesExecuteSimple(ctx, client, "read", roundTripBase+"inline-64k.bin")
			if err != nil || respData.Status != 200 {
				return FailCheck("read failed")
			}
			resultEnt, _ := decodeResultEntity(respData.Result)
			var fd localfiles.FileData
			if err := ecf.Decode(resultEnt.Data, &fd); err != nil {
				return FailCheck("decode file data: " + err.Error())
			}
			blobEnt, ok := env.Included[fd.Content]
			if !ok {
				return FailCheck("blob entity missing from Included at MIN_CHUNK_SIZE")
			}
			blob, err := decodeBlob(blobEnt)
			if err != nil {
				return FailCheck("decode blob: " + err.Error())
			}
			for _, ch := range blob.Chunks {
				if _, ok := env.Included[ch]; !ok {
					return FailCheck(fmt.Sprintf("§4.3: chunk %x missing from Included at size = MIN_CHUNK_SIZE", ch.Digest[:8]))
				}
			}
			return PassCheck(fmt.Sprintf("§4.3: size = MIN_CHUNK_SIZE (%d) → all %d chunks inlined", types.MinChunkSize, len(blob.Chunks)))
		})

		r.Run("inline_include_boundary_above", func() CheckOutcome {
			body := bytes.Repeat([]byte{'B'}, int(types.MinChunkSize)+1)
			_, _, err := localFilesExecuteWrite(ctx, client, body, nil, true, roundTripBase+"inline-64k-plus-1.bin")
			if err != nil {
				return FailCheck("setup write failed: " + err.Error())
			}
			respData, env, err := localFilesExecuteSimple(ctx, client, "read", roundTripBase+"inline-64k-plus-1.bin")
			if err != nil || respData.Status != 200 {
				return FailCheck("read failed")
			}
			resultEnt, _ := decodeResultEntity(respData.Result)
			var fd localfiles.FileData
			if err := ecf.Decode(resultEnt.Data, &fd); err != nil {
				return FailCheck("decode file data: " + err.Error())
			}
			if _, ok := env.Included[fd.Content]; !ok {
				return FailCheck("blob entity should still be in Included above the threshold")
			}
			blobEnt := env.Included[fd.Content]
			blob, err := decodeBlob(blobEnt)
			if err != nil {
				return FailCheck("decode blob: " + err.Error())
			}
			// Above MIN_CHUNK_SIZE chunks MUST NOT be auto-included.
			for _, ch := range blob.Chunks {
				if _, ok := env.Included[ch]; ok {
					return FailCheck(fmt.Sprintf("§4.3: chunk %x should NOT be in Included above MIN_CHUNK_SIZE", ch.Digest[:8]))
				}
			}
			return PassCheck(fmt.Sprintf("§4.3: size = MIN_CHUNK_SIZE+1 (%d) → blob included; chunks not inlined", types.MinChunkSize+1))
		})

		// --- Step 10: Edit stability ---

		r.Run("edit_stability_chunk_reuse", func() CheckOutcome {
			// Build a body large enough to chunk (a few MB so FastCDC
			// produces multiple chunks). The 1-byte edit should disturb at
			// most one chunk boundary.
			const bodySize = 6 * 1024 * 1024 // 6 MiB
			body := make([]byte, bodySize)
			for i := range body {
				body[i] = byte(i % 251)
			}

			_, _, err := localFilesExecuteWrite(ctx, client, body, nil, true, roundTripBase+"edit-base.bin")
			if err != nil {
				return FailCheck("base write failed: " + err.Error())
			}
			respA, _, err := localFilesExecuteSimple(ctx, client, "read", roundTripBase+"edit-base.bin")
			if err != nil || respA.Status != 200 {
				return FailCheck("base read failed")
			}
			entA, _ := decodeResultEntity(respA.Result)
			var fdA localfiles.FileData
			ecf.Decode(entA.Data, &fdA)

			// Read-back included blob carries the chunk list.
			respA2, envA, _ := localFilesExecuteSimple(ctx, client, "read", roundTripBase+"edit-base.bin")
			_ = respA2
			blobA, ok := envA.Included[fdA.Content]
			if !ok {
				return SkipCheck("base blob not in Included (size above threshold); cannot inspect chunk list")
			}
			baseChunks, err := decodeBlobChunks(blobA)
			if err != nil {
				return FailCheck("decode base chunk list: " + err.Error())
			}

			// Flip a single byte in the middle.
			edited := make([]byte, len(body))
			copy(edited, body)
			edited[len(edited)/2] ^= 0xFF

			_, _, err = localFilesExecuteWrite(ctx, client, edited, nil, true, roundTripBase+"edit-edited.bin")
			if err != nil {
				return FailCheck("edited write failed: " + err.Error())
			}
			respB, envB, err := localFilesExecuteSimple(ctx, client, "read", roundTripBase+"edit-edited.bin")
			if err != nil || respB.Status != 200 {
				return FailCheck("edited read failed")
			}
			entB, _ := decodeResultEntity(respB.Result)
			var fdB localfiles.FileData
			ecf.Decode(entB.Data, &fdB)
			blobB, ok := envB.Included[fdB.Content]
			if !ok {
				return SkipCheck("edited blob not in Included")
			}
			editChunks, err := decodeBlobChunks(blobB)
			if err != nil {
				return FailCheck("decode edited chunk list: " + err.Error())
			}

			baseSet := make(map[hash.Hash]struct{}, len(baseChunks))
			for _, c := range baseChunks {
				baseSet[c] = struct{}{}
			}
			reused := 0
			for _, c := range editChunks {
				if _, ok := baseSet[c]; ok {
					reused++
				}
			}
			// FastCDC edit-stability claim: a 1-byte change in the interior of a
			// large file disturbs at most a handful of chunks. The 75% threshold
			// here is a Go-chosen heuristic over an ad-hoc file, NOT a spec MUST —
			// the authoritative, deterministic gate is the CONTENT v3.6 §3.6
			// gear-table + edit-stability vector in the `content` category, where
			// boundaries are pinned. So a low reuse on this ad-hoc file is a WARN
			// (worth a look), not a conformance FAIL.
			minReuse := (len(editChunks) * 3) / 4
			if reused < minReuse {
				return WarnCheck(fmt.Sprintf("edit stability: reused %d / %d chunks on an ad-hoc file (below the %d heuristic) — the authoritative gate is the §3.6 edit-stability vector in `content`", reused, len(editChunks), minReuse))
			}
			return PassCheck(fmt.Sprintf("edit stability: 1-byte edit reused %d / %d chunks", reused, len(editChunks)))
		})
	} else {
		r.Run("local_files_roundtrip_available", func() CheckOutcome {
			return WarnCheck("no writable local/files root advertised by target — " +
				"read/write/list/delete round-trip skipped. Most runs don't mount files, " +
				"so this is expected; to exercise it, start the peer with " +
				"`--files <name>:/dir:local/files/<prefix>/` (the FULL tree prefix).")
		})
	}

	// --- v1.3 behavioral gates (§10.5 Phase 4-bis) ---

	// V1: oversized bytes-mode write must surface a graceful error
	// (wire-frame-too-large at the local SDK or 400/413 at the handler),
	// not a crash / panic / hung connection. Per spec §10.5 V1.
	r.Run("v1_oversized_bytes_mode_graceful", func() CheckOutcome {
		// 20 MiB random — above the V7 default 16 MiB frame max.
		body := make([]byte, 20*1024*1024)
		_, _ = rand.Read(body)
		respData, _, err := localFilesExecuteWrite(ctx, client, body, nil, true, "local/files/test/v1-oversize.bin")
		if err != nil {
			// Wire-layer rejection is the graceful path — connection stays
			// alive, caller gets a diagnosable error. The conformant property
			// is "a clean error, not a crash/hang", independent of the exact
			// phrasing (matching Go's specific "frame too large" string would
			// be a Go-convention gate, not a spec one). We got here with the
			// connection intact and an error in hand, so it's graceful.
			return PassCheck(fmt.Sprintf("§10.5 V1: oversized bytes-mode rejected gracefully at wire layer: %s", err.Error()))
		}
		if respData.Status == 400 || respData.Status == 413 {
			return PassCheck(fmt.Sprintf("§10.5 V1: oversized bytes-mode returned status %d (handler-level rejection)", respData.Status))
		}
		if respData.Status == 200 {
			return FailCheck("§10.5 V1: oversized bytes-mode (20 MiB) returned 200 — impl accepts payloads above the documented wire-frame ceiling; verify or document a peer-side raise")
		}
		return WarnCheck(fmt.Sprintf("§10.5 V1: oversized bytes-mode returned unexpected status %d (not a crash; review)", respData.Status))
	})

	// V2: watcher behavioral check — write to disk bypassing the handler,
	// wait debounce + safety, assert the tree contains the file entity.
	// SKIP if watch isn't declared (L2 MUST-iff-declared makes that a
	// conformant choice); FAIL if declared but propagation doesn't happen.
	r.Run("v2_watcher_fires_on_disk_edit", func() CheckOutcome {
		if out, ok := r.Require("handler_manifest_decode"); !ok {
			return out
		}
		handlerData := r.Load("handler_data").(types.HandlerInterfaceData)
		if _, declared := handlerData.Operations["watch"]; !declared {
			return WarnCheck("§10.5 V2: watch not in manifest — per §10.1 MUST-iff-declared this is conformant; nothing to test")
		}

		rootName, fsRoot, treePrefix, ok := discoverLocalFilesRoot(ctx, client)
		if !ok {
			return WarnCheck("§10.5 V2: no peer root accessible from validator (V2 requires local FS access to peer's --files mount; skipping behavioral check)")
		}

		fileName := fmt.Sprintf("v2-watcher-%d.txt", time.Now().UnixNano())
		fsPath := filepath.Join(fsRoot, fileName)
		body := []byte("v2 watcher behavioral probe — written directly to disk\n")
		if err := os.WriteFile(fsPath, body, 0644); err != nil {
			return WarnCheck("§10.5 V2: cannot write to peer's fs root from validator: " + err.Error())
		}
		defer os.Remove(fsPath)

		// Start watch on the root (idempotent; if a watcher was already
		// running, the handler restarts it; either way the new file is
		// covered by the active watcher).
		wr := localfiles.WatchRequestData{RootName: rootName, Action: "start"}
		rawWR, _ := ecf.Encode(wr)
		watchParams, _ := entity.NewEntity(localfiles.TypeWatchRequest, cbor.RawMessage(rawWR))
		uri := fmt.Sprintf("entity://%s/local/files", client.RemotePeerID())
		watchResource := &types.ResourceTarget{Targets: []string{"local/files"}}
		watchEnv, _, werr := client.SendExecute(ctx, uri, "watch", watchParams, watchResource)
		if werr != nil {
			return FailCheck(fmt.Sprintf("§10.5 V2: watch op errored: %v", werr))
		}
		watchResp, _ := types.ExecuteResponseDataFromEntity(watchEnv.Root)
		if watchResp.Status != 200 {
			return FailCheck(fmt.Sprintf("§10.5 V2: watch op returned status %d (expected 200 since watch is declared)", watchResp.Status))
		}

		// Default debounce is 2000ms per spec §6.3; add 1000ms safety
		// for slower impls (Python's ~3s edit-stability suggests its
		// pipelines need more headroom).
		time.Sleep(3000 * time.Millisecond)

		treePath := treePrefix + fileName
		_, _, err := client.TreeGet(ctx, treePath)
		if err != nil {
			return FailCheck(fmt.Sprintf("§10.5 V2: watch declared in manifest but tree did NOT contain %s after disk write + debounce (§10.1 MUST-iff-declared violated): %v", treePath, err))
		}
		return PassCheck(fmt.Sprintf("§10.5 V2: watcher propagated on-disk edit to tree at %s within debounce", treePath))
	})

	// V3: descriptor publication exercised. Requires a root configured
	// with publish_descriptors=true; SKIP otherwise.
	r.Run("v3_descriptor_publish_exercised", func() CheckOutcome {
		rootName, fsRoot, treePrefix, ok := discoverDescriptorPublishingRoot(ctx, client)
		if !ok {
			return WarnCheck("§10.5 V3: no root with publish_descriptors=true configured — V3 behavioral check not exercised; activate by configuring a root with publish_descriptors")
		}
		_ = rootName

		fileName := fmt.Sprintf("v3-desc-%d.txt", time.Now().UnixNano())
		fsPath := filepath.Join(fsRoot, fileName)
		body := []byte("v3 descriptor publication probe\n")
		if err := os.WriteFile(fsPath, body, 0644); err != nil {
			return WarnCheck("§10.5 V3: cannot write to peer's fs root from validator: " + err.Error())
		}
		defer os.Remove(fsPath)

		treePath := treePrefix + fileName
		respData, _, err := localFilesExecuteSimple(ctx, client, "read", treePath)
		if err != nil || respData.Status != 200 {
			return FailCheck(fmt.Sprintf("§10.5 V3: read failed (status=%d err=%v)", respData.Status, err))
		}
		fileEnt, _ := decodeResultEntity(respData.Result)
		var fd localfiles.FileData
		if err := ecf.Decode(fileEnt.Data, &fd); err != nil {
			return FailCheck("§10.5 V3: decode file entity: " + err.Error())
		}
		if fd.Content.IsZero() {
			return FailCheck("§10.5 V3: file entity has no blob hash")
		}

		// Look for descriptors under system/content/descriptor/{B_hex}/
		// against the remote peer (TreeListing targets remote peer).
		// {B_hex} uses V7 §3.5 invariant-pointer hex (66 chars w/ format byte)
		// per EXTENSION-CONTENT §5.3 (dual-level invariant-pointer convention).
		// Rust + Python emit the same form.
		bHex := hex.EncodeToString(fd.Content.Bytes())
		entries, _, lerr := client.TreeListing(ctx, "system/content/descriptor/"+bHex+"/")
		if lerr != nil {
			return FailCheck(fmt.Sprintf("§10.5 V3: listing descriptors errored: %v", lerr))
		}
		if len(entries) == 0 {
			return FailCheck(fmt.Sprintf("§10.5 V3: publish_descriptors=true on root %q but no descriptor entity at system/content/descriptor/%s/ after read", rootName, bHex[:16]))
		}
		return PassCheck(fmt.Sprintf("§10.5 V3: %d descriptor(s) published under system/content/descriptor/%s…/", len(entries), bHex[:8]))
	})

	// V4: leaf-symlink rejection — cross-impl behavioral gate for the
	// L5 MUST per DOMAIN-LOCAL-FILES v1.3 §8.3. Plant a symlink in the
	// peer's mount pointing outside the root; attempt `local/files:read`
	// on the symlink's tree path; assert 403 with the normatively-pinned
	// `path_traversal_rejected` error code. Convergent fix shape across
	// Rust C-1 + Python F-4 + Go's audit (commit ba21372). Requires the
	// validator to have local FS access to the peer's --files mount
	// (same machine, same shape as V2 / V3).
	//
	// Spec §865: "Both the parent-traversal defense and the leaf-symlink
	// defense MUST surface failure as HTTP-style status 403 with error
	// code path_traversal_rejected."
	r.Run("v4_leaf_symlink_rejected", func() CheckOutcome {
		rootName, fsRoot, treePrefix, ok := discoverLocalFilesRoot(ctx, client)
		if !ok {
			return WarnCheck("§10.5 V4: no peer root accessible from validator (V4 requires local FS access to peer's --files mount; skipping behavioral check)")
		}
		_ = rootName

		// Plant a symlink pointing to a fixed-content target file outside
		// the root. If the leaf-symlink defense fails open, the read will
		// surface the target file's content; if it works, we get 403.
		outsideDir := os.TempDir()
		outsideName := fmt.Sprintf("v4-target-%d.txt", time.Now().UnixNano())
		outsidePath := filepath.Join(outsideDir, outsideName)
		outsideContent := []byte("V4 outside-the-sandbox marker — leaf-symlink defense must refuse this read\n")
		if err := os.WriteFile(outsidePath, outsideContent, 0644); err != nil {
			return WarnCheck("§10.5 V4: cannot stage outside file: " + err.Error())
		}
		defer os.Remove(outsidePath)

		linkName := fmt.Sprintf("v4-escape-%d.txt", time.Now().UnixNano())
		linkFSPath := filepath.Join(fsRoot, linkName)
		if err := os.Symlink(outsidePath, linkFSPath); err != nil {
			return WarnCheck("§10.5 V4: cannot plant symlink in peer root (filesystem may not support symlinks): " + err.Error())
		}
		defer os.Remove(linkFSPath)

		treePath := treePrefix + linkName
		respData, _, err := localFilesExecuteSimple(ctx, client, "read", treePath)
		if err != nil {
			return FailCheck(fmt.Sprintf("§10.5 V4: read errored at wire layer: %v", err))
		}
		if respData.Status >= 200 && respData.Status < 300 {
			return FailCheck(fmt.Sprintf("§10.5 V4: read of leaf-symlink path returned status %d (expected 403 path_traversal_rejected per §8.3 MUST) — leaf-symlink defense is NOT enforced; bytes outside the sandbox may have been exposed", respData.Status))
		}
		if respData.Status != 403 {
			return FailCheck(fmt.Sprintf("§10.5 V4: read of leaf-symlink path returned status %d; spec §8.3/§865 pins 403 path_traversal_rejected (impl rejected for an unrelated reason — verify the leaf-symlink defense is the source)", respData.Status))
		}
		code, codeErr := decodeResultErrorCode(respData)
		if codeErr != nil {
			return FailCheck(fmt.Sprintf("§10.5 V4: 403 returned but error code unreadable: %v (spec §865 requires path_traversal_rejected)", codeErr))
		}
		if code != "path_traversal_rejected" {
			return FailCheck(fmt.Sprintf("§10.5 V4: 403 returned with code=%q; spec §865 pins path_traversal_rejected", code))
		}
		return PassCheck("§10.5 V4: leaf-symlink rejected with 403 path_traversal_rejected (§8.3 MUST + §865 error-code pin)")
	})

	return r.Results()
}

// discoverLocalFilesRoot finds a root whose filesystem_root is accessible
// from the validator process (same machine). Returns (name, fs_root,
// tree_prefix, ok). Used by V2 / V3 which need to bypass the handler.
func discoverLocalFilesRoot(ctx context.Context, client *PeerClient) (string, string, string, bool) {
	entries, _, err := client.TreeListing(ctx, "system/config/local/files/")
	if err != nil || len(entries) == 0 {
		return "", "", "", false
	}
	for name := range entries {
		if strings.Contains(name, "/") || name == "" || name == "watch" {
			continue // skip the watch/ sub-namespace and any compound keys
		}
		ent, _, gerr := client.TreeGet(ctx, "system/config/local/files/"+name)
		if gerr != nil {
			continue
		}
		var cfg localfiles.RootConfigData
		if derr := ecf.Decode(ent.Data, &cfg); derr != nil {
			continue
		}
		if cfg.FilesystemRoot == "" || cfg.Prefix == "" {
			continue
		}
		if info, serr := os.Stat(cfg.FilesystemRoot); serr != nil || !info.IsDir() {
			continue
		}
		probe := filepath.Join(cfg.FilesystemRoot, ".v2-probe-"+fmt.Sprint(time.Now().UnixNano()))
		if werr := os.WriteFile(probe, []byte{}, 0644); werr != nil {
			continue // not writable from validator process
		}
		_ = os.Remove(probe)
		return name, cfg.FilesystemRoot, cfg.Prefix, true
	}
	return "", "", "", false
}

// discoverWritableLocalFilesPrefix returns the tree prefix of the first
// writable local/files root the target advertises at
// system/config/local/files/, for the over-the-wire read/write round-trip.
//
// Unlike discoverLocalFilesRoot, this does NOT require the validator process
// to have local filesystem access to the peer's mount — the round-trip writes
// happen over the wire, so all it needs is a root that is (a) not read_only
// and (b) has a non-empty tree prefix. Returns ("", false) when the target
// advertises no writable root (no --files mount), which the caller surfaces as
// a clean WARN rather than a cascade of 404s.
func discoverWritableLocalFilesPrefix(ctx context.Context, client *PeerClient) (string, bool) {
	entries, _, err := client.TreeListing(ctx, "system/config/local/files/")
	if err != nil || len(entries) == 0 {
		return "", false
	}
	for name := range entries {
		if strings.Contains(name, "/") || name == "" || name == "watch" {
			continue // skip the watch/ sub-namespace and any compound keys
		}
		ent, _, gerr := client.TreeGet(ctx, "system/config/local/files/"+name)
		if gerr != nil {
			continue
		}
		var cfg localfiles.RootConfigData
		if derr := ecf.Decode(ent.Data, &cfg); derr != nil {
			continue
		}
		if cfg.Prefix == "" || cfg.ReadOnly {
			continue
		}
		prefix := cfg.Prefix
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		return prefix, true
	}
	return "", false
}

// discoverDescriptorPublishingRoot finds a root with publish_descriptors=true.
// Returns the same shape as discoverLocalFilesRoot.
func discoverDescriptorPublishingRoot(ctx context.Context, client *PeerClient) (string, string, string, bool) {
	entries, _, err := client.TreeListing(ctx, "system/config/local/files/")
	if err != nil || len(entries) == 0 {
		return "", "", "", false
	}
	for name := range entries {
		if strings.Contains(name, "/") || name == "" || name == "watch" {
			continue
		}
		ent, _, gerr := client.TreeGet(ctx, "system/config/local/files/"+name)
		if gerr != nil {
			continue
		}
		var cfg localfiles.RootConfigData
		if derr := ecf.Decode(ent.Data, &cfg); derr != nil {
			continue
		}
		if !cfg.PublishDescriptors {
			continue
		}
		if cfg.FilesystemRoot == "" || cfg.Prefix == "" {
			continue
		}
		if info, serr := os.Stat(cfg.FilesystemRoot); serr != nil || !info.IsDir() {
			continue
		}
		probe := filepath.Join(cfg.FilesystemRoot, ".v3-probe-"+fmt.Sprint(time.Now().UnixNano()))
		if werr := os.WriteFile(probe, []byte{}, 0644); werr != nil {
			continue
		}
		_ = os.Remove(probe)
		return name, cfg.FilesystemRoot, cfg.Prefix, true
	}
	return "", "", "", false
}

// --- Helpers ---

func decodeResultEntity(raw cbor.RawMessage) (entity.Entity, error) {
	var ent entity.Entity
	if err := ecf.Decode(raw, &ent); err != nil {
		return entity.Entity{}, err
	}
	return ent, nil
}

func decodeBlob(ent entity.Entity) (types.ContentBlobData, error) {
	var blob types.ContentBlobData
	if err := ecf.Decode(ent.Data, &blob); err != nil {
		return types.ContentBlobData{}, err
	}
	return blob, nil
}

func decodeBlobChunks(ent entity.Entity) ([]hash.Hash, error) {
	b, err := decodeBlob(ent)
	if err != nil {
		return nil, err
	}
	return b.Chunks, nil
}

// localBuildBlobHash returns the blob entity hash that the shared
// CONTENT v3.6 substrate would produce for the given bytes. Used by
// cross_handler_dedup_blob_hash to assert that the local/files:read
// path converges on the same value.
func localBuildBlobHash(data []byte) hash.Hash {
	ranges := chunker.ChunkFastCDC(data, types.DefaultChunkSize)
	blobEnt, _, _ := content.BuildBlob(data, ranges, types.ChunkingFastCDC, types.DefaultChunkSize)
	return blobEnt.ContentHash
}

// localFilesExecuteWrite sends a write request. Exactly one of bytes /
// contentRef MUST be set (the §5.4 input-mode invariant).
func localFilesExecuteWrite(ctx context.Context, client *PeerClient, bodyBytes []byte, contentRef *hash.Hash, createDirs bool, resourcePath string) (types.ExecuteResponseData, entity.Envelope, error) {
	wr := localfiles.WriteRequestData{
		Bytes:      bodyBytes,
		Content:    contentRef,
		CreateDirs: createDirs,
	}
	raw, err := ecf.Encode(wr)
	if err != nil {
		return types.ExecuteResponseData{}, entity.Envelope{}, fmt.Errorf("encode write request: %w", err)
	}
	paramsEnt, err := entity.NewEntity(localfiles.TypeWriteRequest, cbor.RawMessage(raw))
	if err != nil {
		return types.ExecuteResponseData{}, entity.Envelope{}, fmt.Errorf("build params entity: %w", err)
	}
	resource := &types.ResourceTarget{Targets: []string{resourcePath}}
	uri := fmt.Sprintf("entity://%s/local/files", client.RemotePeerID())
	env, _, err := client.SendExecute(ctx, uri, "write", paramsEnt, resource)
	if err != nil {
		return types.ExecuteResponseData{}, entity.Envelope{}, err
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return types.ExecuteResponseData{}, entity.Envelope{}, fmt.Errorf("decode response: %w", err)
	}
	return respData, env, nil
}

// localFilesExecuteSimple sends a parameterless operation (read, list,
// delete) and returns the response + envelope. Envelope carries the
// CONTENT §4.3 inline-include map.
func localFilesExecuteSimple(ctx context.Context, client *PeerClient, operation, resourcePath string) (types.ExecuteResponseData, entity.Envelope, error) {
	raw, _ := ecf.Encode(map[string]interface{}{})
	paramsEnt, err := entity.NewEntity("primitive/map", cbor.RawMessage(raw))
	if err != nil {
		return types.ExecuteResponseData{}, entity.Envelope{}, fmt.Errorf("build params entity: %w", err)
	}
	resource := &types.ResourceTarget{Targets: []string{resourcePath}}
	uri := fmt.Sprintf("entity://%s/local/files", client.RemotePeerID())
	env, _, err := client.SendExecute(ctx, uri, operation, paramsEnt, resource)
	if err != nil {
		return types.ExecuteResponseData{}, entity.Envelope{}, err
	}
	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return types.ExecuteResponseData{}, entity.Envelope{}, fmt.Errorf("decode response: %w", err)
	}
	return respData, env, nil
}
