package api

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestOrgPermissionInputsIgnoreActorJSON(t *testing.T) {
	trusted := OrgPermissionActor{OrgID: "trusted-org", UserID: "trusted-user", SessionID: "trusted-session"}
	actor := trusted
	if err := json.Unmarshal([]byte(`{"orgId":"forged","userId":"forged","sessionId":"forged"}`), &actor); err != nil {
		t.Fatal(err)
	}
	if actor != trusted {
		t.Fatalf("JSON replaced the trusted actor: %+v", actor)
	}
	data, err := json.Marshal(actor)
	if err != nil || string(data) != `{}` {
		t.Fatalf("actor JSON = %s, error = %v", data, err)
	}

	inputs := []any{
		InitializeOrgPermissionsInput{}, CheckOrgPermissionInput{},
		CreateOrgPermissionInput{}, UpdateOrgPermissionInput{}, DeleteOrgPermissionInput{}, ListOrgPermissionsInput{},
		CreateOrgRoleInput{}, UpdateOrgRoleInput{}, SetOrgRolePermissionsInput{}, DeleteOrgRoleInput{}, ListOrgRolesInput{},
		SetOrgMemberRoleInput{}, GetOrgMemberRoleInput{}, ListOrgEffectivePermissionsInput{}, UpdateOrgLibraryPermissionsInput{},
	}
	for _, input := range inputs {
		inputType := reflect.TypeOf(input)
		t.Run(inputType.Name(), func(t *testing.T) {
			value := reflect.New(inputType)
			value.Elem().FieldByName("Actor").Set(reflect.ValueOf(trusted))
			if err := json.Unmarshal([]byte(`{"actor":{"orgId":"forged","userId":"forged","sessionId":"forged"}}`), value.Interface()); err != nil {
				t.Fatal(err)
			}
			if got := value.Elem().FieldByName("Actor").Interface(); got != trusted {
				t.Fatalf("JSON replaced trusted context: %+v", got)
			}
			data, err := json.Marshal(value.Interface())
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"actor", "Actor"} {
				if _, found := fields[key]; found {
					t.Fatalf("JSON exposed trusted context: %s", data)
				}
			}
		})
	}
}
