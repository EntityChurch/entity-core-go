package inbox

import (
	"context"
	"fmt"
	"log"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

const handlerPattern = "system/inbox"

// Handler implements the system/inbox handler with a single receive operation.
// When a continuation exists at the inbox path, the handler delegates to the
// continuation handler's advance operation. Otherwise it stores the message.
type Handler struct {
	debugLog *log.Logger
}

// NewHandler creates a new inbox handler.
func NewHandler() *Handler {
	return &Handler{}
}

// SetDebugLog enables debug logging for the inbox handler.
func (h *Handler) SetDebugLog(l *log.Logger) {
	h.debugLog = l
}

func (h *Handler) debugf(format string, args ...any) {
	if h.debugLog != nil {
		h.debugLog.Printf("inbox: "+format, args...)
	}
}

func (h *Handler) Name() string { return "inbox" }

// Manifest returns the handler's self-description.
func (h *Handler) Manifest() types.HandlerManifestData {
	return types.HandlerManifestData{
		Pattern: handlerPattern,
		Name:    "inbox",
		Operations: map[string]types.HandlerOperationSpec{
			"receive": {InputType: "primitive/any"},
		},
	}
}

// RegisterTypes registers inbox-specific types into the registry.
// Note: system/delivery-spec is already registered in RegisterCoreTypes with
// semantic type overrides (uri → system/tree/path). Do not re-register here.
func (h *Handler) RegisterTypes(r *types.TypeRegistry) {}

// Handle dispatches to the appropriate operation.
func (h *Handler) Handle(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	switch req.Operation {
	case "receive":
		return h.handleReceive(ctx, req)
	default:
		return handler.NewErrorResponse(400, "unknown_operation",
			"inbox handler does not support operation: "+req.Operation)
	}
}

// handleReceive implements the receive operation.
func (h *Handler) handleReceive(ctx context.Context, req *handler.Request) (*handler.Response, error) {
	hctx := req.Context
	if hctx == nil || hctx.Store == nil || hctx.LocationIndex == nil {
		return handler.NewErrorResponse(500, "internal_error", "missing store or location index")
	}

	// Extract inbox path from resource target.
	path := hctx.ExtractResourcePath()
	if path == "" {
		return handler.NewErrorResponse(400, "invalid_params", "resource target path is required")
	}

	// Level 2 capability check.
	if resp := hctx.CheckPathCapability("receive", path); resp != nil {
		return resp, nil
	}

	// Write-ahead: store message entity at {inbox_path}/{uuid}.
	storageKey := hctx.RequestID
	if storageKey == "" {
		storageKey = fmt.Sprintf("%d", cbor.RawMessage(req.Params.Data))
	}
	storagePath := path + "/" + storageKey

	storedHash, err := hctx.Store.Put(req.Params)
	if err != nil {
		return nil, fmt.Errorf("store message: %w", err)
	}
	if _, err := hctx.TreeSet(storagePath, storedHash, "receive"); err != nil {
		return nil, fmt.Errorf("bind message %s: %w", storagePath, err)
	}

	// Check for continuation at inbox path.
	contentHash, ok := hctx.LocationIndex.Get(path)
	if ok {
		ent, entOk := hctx.Store.Get(contentHash)
		if entOk && (ent.Type == types.TypeContinuation || ent.Type == types.TypeContinuationJoin) {
			h.debugf("continuation found at %s (type=%s), delegating to advance", path, ent.Type)
		}
	} else {
		h.debugf("no continuation at %s, storing as mailbox message", path)
	}
	// Re-get for the type check below (don't shadow the variable).
	contentHash, ok = hctx.LocationIndex.Get(path)
	if ok {
		ent, entOk := hctx.Store.Get(contentHash)
		if entOk && (ent.Type == types.TypeContinuation || ent.Type == types.TypeContinuationJoin) {
			h.debugf("continuation found at %s (type=%s), delegating to advance", path, ent.Type)
			// Delegate to continuation handler's advance operation.
			// Run async to avoid blocking the serve loop — continuation dispatch
			// may make remote calls that deadlock if the serve loop is blocked.
			if hctx.Execute != nil {
				// Unwrap delivery result per EXTENSION-INBOX §3.2:
				// If the message is a delivery, extract .result and .status.
				// Otherwise use the raw message data.
				advResult, advStatus := unwrapDeliveryResult(req.Params)
				advReq := types.ContinuationAdvanceRequestData{
					Result: advResult,
					Status: advStatus,
				}
				advEntity, err := advReq.ToEntity()
				if err == nil {
					resource := &types.ResourceTarget{Targets: []string{path}}
					advanceFn := func() {
						resp, err := hctx.Execute(ctx, "system/continuation", "advance", advEntity,
							handler.WithResource(resource))
						if err != nil {
							h.debugf("advance error at %s: %v", path, err)
						} else if resp != nil {
							var advResult map[string]interface{}
							cbor.Unmarshal(resp.Result.Data, &advResult)
							h.debugf("advance at %s: status=%d advanced=%v", path, resp.Status, advResult["advanced"])
							// Clean up write-ahead message on success.
							if advResult["advanced"] == true {
								hctx.TreeRemove(storagePath, "receive")
							}
						}
					}
					// Run the advance on the dispatcher's bounded async pool
					// so the serve loop isn't blocked (continuation dispatch
					// may make remote calls). GoAsync is nil only for
					// manually-built test contexts — preserve the prior
					// unbounded behavior there.
					submitted := true
					if hctx.GoAsync != nil {
						submitted = hctx.GoAsync(advanceFn)
					} else {
						go advanceFn()
					}
					if submitted {
						// Return 200 immediately — advance runs async.
						resultRaw, _ := ecf.Encode(map[string]interface{}{"accepted": true})
						resultEntity, _ := entity.NewEntity("system/inbox/receive-result", cbor.RawMessage(resultRaw))
						return &handler.Response{Status: 200, Result: resultEntity}, nil
					}
					// Pool saturated: do NOT spawn an unbounded goroutine.
					// The message is durably write-ahead stored at
					// storagePath, so fall through to the mailbox response
					// below — lossless backpressure. The continuation
					// advances on the next receive or manual drain
					// (EXTENSION-INBOX §3.2 mailbox fallback / §9.3
					// backpressure).
					h.debugf("advance pool saturated at %s; message retained as mailbox for later advancement", path)
				}
			}
		}
	}

	// No continuation or advancement failed — message stays in tree (mailbox).
	resultRaw, _ := ecf.Encode(map[string]interface{}{
		"content_hash": storedHash.Bytes(),
		"path":         storagePath,
	})
	resultEntity, _ := entity.NewEntity("system/inbox/receive-result", cbor.RawMessage(resultRaw))
	return &handler.Response{Status: 200, Result: resultEntity}, nil
}

// unwrapDeliveryResult extracts the result and status from an inbox message entity
// per EXTENSION-INBOX §3.2. If the message is a delivery (system/protocol/inbox/delivery),
// returns data.result and data.status. Otherwise returns the raw entity data and status 200.
func unwrapDeliveryResult(msg entity.Entity) (cbor.RawMessage, *uint) {
	if msg.Type == types.TypeInboxDelivery {
		delivery, err := types.InboxDeliveryDataFromEntity(msg)
		if err == nil {
			status := delivery.Status
			if status == 0 {
				status = 200
			}
			return delivery.Result, &status
		}
	}
	// Not a delivery — use the raw entity data as the result.
	return msg.Data, nil
}
