package content

import (
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/hash"
	"go.entitychurch.org/entity-core-go/core/types"
)

func decodeRequestParams(req handler.ExecuteRequest, out any) error {
	return ecf.Decode(req.Params.Data, out)
}

func decodeEntityData(ent entity.Entity, out any) error {
	return ecf.Decode(ent.Data, out)
}

func buildExecuteResponse(found, missing []hash.Hash, included map[hash.Hash]any) handler.ExecuteResponse {
	respData := types.ContentGetResponseData{Found: found, Missing: missing}
	resultEnt, _ := respData.ToEntity()
	inc := make(map[hash.Hash]entity.Entity, len(included))
	for k, v := range included {
		if e, ok := v.(entity.Entity); ok {
			inc[k] = e
		}
	}
	return handler.ExecuteResponse{
		Status:   200,
		Result:   resultEnt,
		Included: inc,
	}
}
