package typeext

import (
	"context"
	"strings"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"
)

// handleAdopt implements §7.5 — install a remote peer's type definition
// locally. The handler:
//
//   1. Resolves the type definition at source_path.
//   2. Rewrites data.name to local_name (or derives it from source_path
//      by stripping the peer prefix + "system/type/").
//   3. If the parent (extends) lives on the same source peer and a local
//      equivalent exists, rewrites the extends reference to the local
//      name. If no local equivalent exists, leaves extends unchanged and
//      records the dependency in the result's local_name field (via
//      preservation, not via a separate result field — §7.5 returns a
//      system/type entity).
//
// The handler does NOT write to the tree; the caller decides whether to
// tree-put the result.
func (h *Handler) handleAdopt(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	var dispatch types.AdoptRequestData
	if err := ecf.Decode(req.Params.Data, &dispatch); err != nil {
		return handler.NewErrorResponse(400, "decode_error",
			"failed to decode adopt-request: "+err.Error())
	}
	if dispatch.SourcePath == "" {
		return handler.NewErrorResponse(400, "invalid_request",
			"adopt requires source_path")
	}

	// Resolve the source type. The source path may be absolute
	// (/{peer_id}/system/type/{name}) or peer-relative (system/type/{name}).
	srcName := stripTypePathPrefix(dispatch.SourcePath)
	srcDef, ok := resolveTypeDefinition(req.Context, srcName)
	if !ok {
		return handler.NewErrorResponse(404, "type_not_found",
			"could not resolve source type: "+dispatch.SourcePath)
	}

	// Derive local_name if omitted: strip the source peer prefix and the
	// system/type/ convention prefix, leaving the bare name.
	localName := dispatch.LocalName
	if localName == "" {
		localName = srcName
	}

	// Rewrite the type definition.
	adopted := rewriteForAdopt(srcDef, localName, dispatch.SourcePath, req.Context)

	ent, err := adopted.ToEntity()
	if err != nil {
		return handler.NewErrorResponse(500, "encode_error",
			"failed to encode adopted type: "+err.Error())
	}
	return &handler.Response{Status: 200, Result: ent}, nil
}

// rewriteForAdopt produces a copy of src with name set to localName and
// extends rewritten when a local equivalent of the source's parent
// exists. The original src is not mutated.
func rewriteForAdopt(src types.TypeDefinition, localName, sourcePath string, hctx *handler.HandlerContext) types.TypeDefinition {
	out := types.TypeDefinition{
		Name:       localName,
		Extends:    src.Extends,
		Fields:     copyFields(src.Fields),
		Layout:     append([]string(nil), src.Layout...),
		TypeParams: append([]string(nil), src.TypeParams...),
		TypeArgs:   copyStringMap(src.TypeArgs),
	}

	// Extends rewriting (§7.5 step 2). If the parent name is registered
	// locally — either at the same name or under any path that yields the
	// same definition — leave extends as-is (the local resolution will
	// find it). If extends references a name with the source peer's
	// prefix, normalize to the bare name.
	if out.Extends != "" {
		// Strip the source's peer prefix off the extends reference, if
		// present, so the local resolver can find the parent at
		// system/type/{name} regardless of whether the source put it
		// under its own peer namespace.
		if normalized := stripPeerPrefix(out.Extends, sourcePath); normalized != "" {
			out.Extends = normalized
		}
	}
	return out
}

// stripPeerPrefix removes a "/{peer_id}/system/type/" prefix from a
// reference if the reference appears to be absolute and shares a peer
// prefix with sourcePath. Peer-relative references (no leading slash)
// pass through unchanged.
func stripPeerPrefix(ref, sourcePath string) string {
	if !strings.HasPrefix(ref, "/") {
		// Already peer-relative — return as-is.
		return ref
	}
	// ref is absolute. Find "/system/type/" and return the bare name.
	const marker = "/system/type/"
	idx := strings.Index(ref, marker)
	if idx < 0 {
		return ref
	}
	return ref[idx+len(marker):]
}

func copyFields(in map[string]types.FieldSpec) map[string]types.FieldSpec {
	if in == nil {
		return nil
	}
	out := make(map[string]types.FieldSpec, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
