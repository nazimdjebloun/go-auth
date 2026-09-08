package goauth

import "testing"

func TestNewSMTPMailer_EmptyHost(t *testing.T) {
	_, err := NewSMTPMailer(EmailConfig{From: "auth@example.com"})
	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestNewSMTPMailer_EmptyFrom(t *testing.T) {
	_, err := NewSMTPMailer(EmailConfig{Host: "smtp.example.com"})
	if err == nil {
		t.Fatal("expected error for empty from address")
	}
}

func TestNewSMTPMailer_Valid(t *testing.T) {
	mailer, err := NewSMTPMailer(EmailConfig{
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
