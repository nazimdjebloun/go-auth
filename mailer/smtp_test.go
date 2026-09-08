package mailer

import "testing"

func TestNewSMTP_EmptyHost(t *testing.T) {
	_, err := NewSMTP(Config{From: "auth@example.com"})
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestNewSMTP_EmptyFrom(t *testing.T) {
	_, err := NewSMTP(Config{Host: "smtp.example.com"})
	if err == nil {
		t.Fatal("expected error for empty from address")
	}
}

func TestNewSMTP_Valid(t *testing.T) {
	mailer, err := NewSMTP(Config{
		Host: "smtp.example.com",
		From: "auth@example.com",
		Port: 587,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mailer == nil {
		t.Fatal("expected mailer")
	}
}
