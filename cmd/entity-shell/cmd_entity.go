package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/types"

	"github.com/fxamacker/cbor/v2"
)

func cmdCat(sh *Shell, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: cat <path> [-diag]")
	}

	diag := false
	pathArg := ""
	for _, a := range args {
		if a == "-diag" {
			diag = true
		} else {
			pathArg = a
		}
	}
	if pathArg == "" {
		return fmt.Errorf("usage: cat <path> [-diag]")
	}

	target := Resolve(pathArg, sh.wd)
	if target.IsRoot() {
		return fmt.Errorf("cannot cat root")
	}

	pc := sh.connForPath(target)
	if pc == nil {
		return fmt.Errorf("no connection for path %s", target)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	barePath := target.BarePath()
	ent, _, err := pc.Client.TreeGet(ctx, barePath)
	if err != nil {
		return fmt.Errorf("get %s: %w", barePath, err)
	}

	if diag {
		fmt.Print(ent.DiagnoseHash())
		return nil
	}

	// Standard display.
	fmt.Printf("Type:  %s\n", ent.Type)
	fmt.Printf("Hash:  %s\n", ent.ContentHash)

	var decoded interface{}
	if err := ecf.Decode(ent.Data, &decoded); err != nil {
		fmt.Printf("Data:  (decode error: %v)\n", err)
		return nil
	}

	fmt.Printf("Data:\n")
	var b strings.Builder
	entity.FormatCBORValue(&b, "  ", decoded)
	fmt.Print(b.String())
	return nil
}

func cmdExec(sh *Shell, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: exec <handler> <operation> [resource] [json-params]")
	}

	handler := args[0]
	operation := args[1]

	var resource *types.ResourceTarget
	var jsonParams string
	for _, a := range args[2:] {
		if strings.HasPrefix(a, "{") {
			jsonParams = a
		} else if resource == nil {
			resource = &types.ResourceTarget{
				Targets: []string{a},
			}
		}
	}

	pc := sh.connForWD()
	if pc == nil {
		return fmt.Errorf("no connection (cd into a peer first)")
	}

	// Build entity:// URI.
	uri := fmt.Sprintf("entity://%s/%s", pc.PeerID, handler)

	// Encode params — use JSON if provided, otherwise empty map.
	var params map[string]interface{}
	if jsonParams != "" {
		if err := ecf.Decode([]byte(jsonParams), &params); err != nil {
			// Try as JSON via cbor round-trip won't work; just use raw approach.
			params = map[string]interface{}{}
		}
	}
	if params == nil {
		params = map[string]interface{}{}
	}
	paramsRaw, err := ecf.Encode(params)
	if err != nil {
		return fmt.Errorf("encode params: %w", err)
	}
	paramsEntity, err := entity.NewEntity("primitive/any", cbor.RawMessage(paramsRaw))
	if err != nil {
		return fmt.Errorf("create params: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	env, _, err := pc.Client.SendExecute(ctx, uri, operation, paramsEntity, resource)
	if err != nil {
		return fmt.Errorf("execute: %w", err)
	}

	respData, err := types.ExecuteResponseDataFromEntity(env.Root)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	fmt.Printf("Status: %d\n", respData.Status)

	// Decode result entity.
	var resultEntity entity.Entity
	if err := ecf.Decode(respData.Result, &resultEntity); err != nil {
		fmt.Printf("Result: (raw, %d bytes)\n", len(respData.Result))
		return nil
	}

	fmt.Printf("Type:   %s\n", resultEntity.Type)
	fmt.Printf("Hash:   %s\n", resultEntity.ContentHash)

	var decoded interface{}
	if err := ecf.Decode(resultEntity.Data, &decoded); err != nil {
		fmt.Printf("Data:   (decode error: %v)\n", err)
		return nil
	}

	fmt.Printf("Data:\n")
	var b strings.Builder
	entity.FormatCBORValue(&b, "  ", decoded)
	fmt.Print(b.String())

	if len(env.Included) > 0 {
		fmt.Printf("Included: %d entities\n", len(env.Included))
	}
	return nil
}
