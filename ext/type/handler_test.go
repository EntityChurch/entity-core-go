package typeext

import (
	"context"
	"strings"
	"testing"

	"go.entitychurch.org/entity-core-go/core/crypto"
	"go.entitychurch.org/entity-core-go/core/ecf"
	"go.entitychurch.org/entity-core-go/core/entity"
	"go.entitychurch.org/entity-core-go/core/handler"
	"go.entitychurch.org/entity-core-go/core/store"
	"go.entitychurch.org/entity-core-go/core/types"
	"go.entitychurch.org/entity-core-go/ext/type/constraint"

	"github.com/fxamacker/cbor/v2"
)

// testEnv wires a content store + location index + the type handler and the
// standard constraint handler, with an Execute func that routes
// system/type/constraint/* requests to the in-memory constraint handler.
type testEnv struct {
	cs           store.ContentStore
	nsLI         *store.NamespacedIndex
	peerID       crypto.PeerID
	typeHandler  *Handler
	constHandler *constraint.Handler
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	kp, _ := crypto.Generate()
	cs := store.NewMemoryContentStore()
	raw := store.NewMemoryLocationIndex()
	nsLI := store.NewNamespacedIndex(raw, string(kp.PeerID()))
	return &testEnv{
		cs:           cs,
		nsLI:         nsLI,
		peerID:       kp.PeerID(),
		typeHandler:  NewHandler(),
		constHandler: constraint.NewHandler(),
	}
}

// install stores a type definition at system/type/{name}.
func (e *testEnv) install(t *testing.T, def types.TypeDefinition) {
	t.Helper()
	ent, err := def.ToEntity()
	if err != nil {
		t.Fatalf("install %s: ToEntity: %v", def.Name, err)
	}
	h, err := e.cs.Put(ent)
	if err != nil {
		t.Fatalf("install %s: cs.Put: %v", def.Name, err)
	}
	if err := e.nsLI.Set("system/type/"+def.Name, h); err != nil {
		t.Fatalf("install %s: nsLI.Set: %v", def.Name, err)
	}
}

// execute routes dispatch requests from inside the handler to the
// constraint handler. Only system/type/constraint/* paths are recognized;
// everything else surfaces as a dispatch failure (mimicking the no-handler
// case).
func (e *testEnv) execute(ctx context.Context, uri, op string, params entity.Entity, _ ...handler.ExecuteOption) (*handler.Response, error) {
	if !strings.HasPrefix(uri, "system/type/constraint/") {
		return handler.NewErrorResponse(404, "no_handler", "no handler for "+uri)
	}
	req := &handler.Request{
		Operation: op,
		Params:    params,
		Context:   e.hctx(),
	}
	return e.constHandler.Handle(ctx, req)
}

func (e *testEnv) hctx() *handler.HandlerContext {
	return &handler.HandlerContext{
		Store:         e.cs,
		LocationIndex: e.nsLI,
		LocalPeerID:   e.peerID,
		Execute:       e.execute,
	}
}

// validate invokes the type handler's validate op against the given
// entity, optionally pinning a type path. Returns the decoded result.
func (e *testEnv) validate(t *testing.T, subject entity.Entity, typePath string) types.ValidateResultData {
	t.Helper()
	dispatch := types.ValidateRequestData{TypePath: typePath}
	// Re-encode the entity into the dispatch envelope's `entity` field.
	subjectBytes, err := ecf.Encode(subject)
	if err != nil {
		t.Fatalf("encode subject: %v", err)
	}
	dispatch.Entity = cbor.RawMessage(subjectBytes)
	paramEnt, err := dispatch.ToEntity()
	if err != nil {
		t.Fatalf("encode validate-request: %v", err)
	}
	req := &handler.Request{
		Operation: "validate",
		Params:    paramEnt,
		Context:   e.hctx(),
	}
	resp, err := e.typeHandler.Handle(context.Background(), req)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if resp.Status != 200 {
		t.Fatalf("Handle status %d", resp.Status)
	}
	var result types.ValidateResultData
	if err := ecf.Decode(resp.Result.Data, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return result
}

// makeEntity is a small helper for constructing entities by type+data
// inline in tests. Hash is computed automatically.
func makeEntity(t *testing.T, typ string, data interface{}) entity.Entity {
	t.Helper()
	raw, err := ecf.Encode(data)
	if err != nil {
		t.Fatalf("encode %s: %v", typ, err)
	}
	ent, err := entity.NewEntity(typ, cbor.RawMessage(raw))
	if err != nil {
		t.Fatalf("NewEntity %s: %v", typ, err)
	}
	return ent
}

// TestValidatePassesCleanEntity — a structurally sound entity with no
// constraint violations gets valid:true and no violations.
func TestValidatePassesCleanEntity(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "app/user",
		Fields: map[string]types.FieldSpec{
			"name": {TypeRef: "primitive/string"},
			"age":  {TypeRef: "primitive/uint", Optional: true},
		},
	})
	subj := makeEntity(t, "app/user", map[string]interface{}{
		"name": "alice",
		"age":  uint64(30),
	})

	r := env.validate(t, subj, "app/user")
	if !r.Valid {
		t.Errorf("want valid:true, got violations=%+v", r.Violations)
	}
}

// TestValidateMissingRequiredField yields a structural violation.
func TestValidateMissingRequiredField(t *testing.T) {
	env := newTestEnv(t)
	env.install(t, types.TypeDefinition{
		Name: "app/user",
		Fields: map[string]types.FieldSpec{
			"name": {TypeRef: "primitive/string"},
		},
	})
	subj := makeEntity(t, "app/user", map[string]interface{}{})

	r := env.validate(t, subj, "")
	if r.Valid {
		t.Fatal("want valid:false for missing required field")
	}
	if len(r.Violations) != 1 || r.Violations[0].Kind != types.ViolationKindStructural {
		t.Errorf("want one structural violation, got %+v", r.Violations)
	}
}

// TestValidateDispatchesConstraints — a min_length:1 constraint on a name
// field rejects the empty string with kind=constraint.
func TestValidateDispatchesConstraints(t *testing.T) {
	env := newTestEnv(t)
	minLen, err := types.ConstraintMinLengthData{MinLength: 1}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	env.install(t, types.TypeDefinition{
		Name: "app/user",
		Fields: map[string]types.FieldSpec{
			"name": {
				TypeRef:     "primitive/string",
				Constraints: []entity.Entity{minLen},
			},
		},
	})
	subj := makeEntity(t, "app/user", map[string]interface{}{"name": ""})

	r := env.validate(t, subj, "")
	if r.Valid {
		t.Fatalf("empty name should fail min_length:1: %+v", r)
	}
	if len(r.Violations) != 1 {
		t.Fatalf("want one violation, got %d: %+v", len(r.Violations), r.Violations)
	}
	v := r.Violations[0]
	if v.Field != "name" || v.Kind != types.ViolationKindConstraint || v.Constraint != types.TypeConstraintMinLength {
		t.Errorf("violation = %+v; want field=name kind=constraint constraint=min_length", v)
	}
}

// TestValidateUnknownConstraintFailsClosed — an unknown constraint type
// surfaces as kind=unknown_constraint, not silent pass. Required by §1.2.
func TestValidateUnknownConstraintFailsClosed(t *testing.T) {
	env := newTestEnv(t)
	// Custom constraint at a path with no registered handler.
	rogue, err := entity.NewEntity("system/type/constraint/rogue",
		cbor.RawMessage([]byte{0xa0})) // empty map
	if err != nil {
		t.Fatal(err)
	}
	env.install(t, types.TypeDefinition{
		Name: "app/thing",
		Fields: map[string]types.FieldSpec{
			"x": {
				TypeRef:     "primitive/string",
				Constraints: []entity.Entity{rogue},
			},
		},
	})
	subj := makeEntity(t, "app/thing", map[string]interface{}{"x": "anything"})

	r := env.validate(t, subj, "")
	if r.Valid {
		t.Fatal("unknown constraint MUST NOT silent-pass (§1.2)")
	}
	if len(r.Violations) != 1 || r.Violations[0].Kind != types.ViolationKindUnknownConstraint {
		t.Errorf("want kind=unknown_constraint, got %+v", r.Violations)
	}
}

// TestValidateUnknownFormatSurfacesAsUnknownConstraint — §4.5: the
// standard constraint handler reports unknown format names with valid:false
// + "unknown format" marker; the type handler reflects this as
// kind=unknown_constraint, not kind=constraint.
func TestValidateUnknownFormatSurfacesAsUnknownConstraint(t *testing.T) {
	env := newTestEnv(t)
	fmtConstraint, err := types.ConstraintFormatData{Format: "email"}.ToEntity()
	if err != nil {
		t.Fatal(err)
	}
	env.install(t, types.TypeDefinition{
		Name: "app/contact",
		Fields: map[string]types.FieldSpec{
			"email": {
				TypeRef:     "primitive/string",
				Constraints: []entity.Entity{fmtConstraint},
			},
		},
	})
	subj := makeEntity(t, "app/contact", map[string]interface{}{"email": "a@b.c"})

	r := env.validate(t, subj, "")
	if r.Valid {
		t.Fatal("unknown format MUST surface as unknown_constraint")
	}
	if len(r.Violations) == 0 || r.Violations[0].Kind != types.ViolationKindUnknownConstraint {
		t.Errorf("want kind=unknown_constraint for unknown format, got %+v", r.Violations)
	}
}

// TestValidateAbsentOptionalFieldSkipsConstraints — §2.3: absent optional
// fields are not constraint-checked.
func TestValidateAbsentOptionalFieldSkipsConstraints(t *testing.T) {
	env := newTestEnv(t)
	minLen, _ := types.ConstraintMinLengthData{MinLength: 1}.ToEntity()
	env.install(t, types.TypeDefinition{
		Name: "app/nickname",
		Fields: map[string]types.FieldSpec{
			"nick": {
				TypeRef:     "primitive/string",
				Optional:    true,
				Constraints: []entity.Entity{minLen},
			},
		},
	})
	subj := makeEntity(t, "app/nickname", map[string]interface{}{})

	r := env.validate(t, subj, "")
	if !r.Valid {
		t.Errorf("absent optional field with constraint should not violate: %+v", r.Violations)
	}
}

// TestValidateTypeNotResolvable — when the type can't be looked up via
// Strategy 1, the validator returns a structural violation rather than
// silently passing.
func TestValidateTypeNotResolvable(t *testing.T) {
	env := newTestEnv(t)
	subj := makeEntity(t, "app/missing", map[string]interface{}{})

	r := env.validate(t, subj, "")
	if r.Valid {
		t.Fatal("unknown type MUST yield a violation")
	}
	if r.Violations[0].Kind != types.ViolationKindStructural {
		t.Errorf("want structural violation for unresolved type, got %+v", r.Violations[0])
	}
}
