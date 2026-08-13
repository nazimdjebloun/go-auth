package keyring

import "testing"

func TestDerive_Deterministic(t *testing.T) {
	secret := []byte("a fixed test secret, 32+ bytes long")
	k1 := Derive(secret)
	k2 := Derive(secret)

	if string(k1.CSRF) != string(k2.CSRF) {
		t.Error("CSRF key differs across Derive calls with the same secret")
	}
	if string(k1.OAuthEnc) != string(k2.OAuthEnc) {
		t.Error("OAuthEnc key differs across Derive calls with the same secret")
	}
	if string(k1.TwoFactor) != string(k2.TwoFactor) {
		t.Error("TwoFactor key differs across Derive calls with the same secret")
	}
}

func TestDerive_KeysArePairwiseDistinct(t *testing.T) {
	k := Derive([]byte("another fixed test secret"))

	if string(k.CSRF) == string(k.OAuthEnc) {
		t.Error("CSRF and OAuthEnc keys must not be equal")
	}
	if string(k.CSRF) == string(k.TwoFactor) {
		t.Error("CSRF and TwoFactor keys must not be equal")
	}
	if string(k.OAuthEnc) == string(k.TwoFactor) {
		t.Error("OAuthEnc and TwoFactor keys must not be equal")
	}
}

func TestDerive_DifferentSecretsProduceDifferentKeys(t *testing.T) {
	k1 := Derive([]byte("secret one"))
	k2 := Derive([]byte("secret two"))

	if string(k1.CSRF) == string(k2.CSRF) {
		t.Error("expected different secrets to derive different CSRF keys")
	}
	if string(k1.OAuthEnc) == string(k2.OAuthEnc) {
		t.Error("expected different secrets to derive different OAuthEnc keys")
	}
	if string(k1.TwoFactor) == string(k2.TwoFactor) {
		t.Error("expected different secrets to derive different TwoFactor keys")
	}
}

func TestDerive_OutputLengthIs32Bytes(t *testing.T) {
	k := Derive([]byte("length check secret"))

	if len(k.CSRF) != 32 {
		t.Errorf("expected CSRF key to be 32 bytes, got %d", len(k.CSRF))
	}
	if len(k.OAuthEnc) != 32 {
		t.Errorf("expected OAuthEnc key to be 32 bytes, got %d", len(k.OAuthEnc))
	}
	if len(k.TwoFactor) != 32 {
		t.Errorf("expected TwoFactor key to be 32 bytes, got %d", len(k.TwoFactor))
	}
}
