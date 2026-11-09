package api

import (
	"encoding/json"
	"testing"
)

func TestActorIdentityCannotCrossJSONBoundary(t *testing.T) {
	actor := Actor{UserID: "trusted-user", SessionID: "trusted-session"}
	// App permissions accept the same value without rebuilding another actor.
	var appActor = actor
	for _, test := range []struct {
		name  string
		value any
	}{
		{name: "actor", value: actor},
		{name: "app actor", value: appActor},
		{name: "org actor", value: actor.ForOrg("selected-org")},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != "{}" {
				t.Fatalf("identity serialized: %s", encoded)
			}
		})
	}
	var decoded Actor
	if err := json.Unmarshal([]byte(`{"userId":"forged","UserID":"forged","sessionId":"forged","SessionID":"forged"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != (Actor{}) {
		t.Fatalf("JSON populated trusted identity: %+v", decoded)
	}
}
