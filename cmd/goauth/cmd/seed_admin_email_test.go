package cmd

import (
	"strings"
	"testing"
)

func TestAdminAccountCreatedEmail_HTMLIsAWellFormedCard(t *testing.T) {
	_, html, _ := adminAccountCreatedEmail()

	for _, want := range []string{"<!DOCTYPE html>", "<html", "</html>", "<h1", "</body>"} {
		if !strings.Contains(html, want) {
			t.Errorf("expected the HTML body to contain %q", want)
		}
	}
	if !strings.Contains(html, "Your admin account is ready") {
		t.Error("expected the heading text in the HTML body")
	}
}

func TestAdminAccountCreatedEmail_TextIsPlain(t *testing.T) {
	_, _, text := adminAccountCreatedEmail()

	if strings.ContainsAny(text, "<>") {
		t.Errorf("expected no markup in the text body, got %q", text)
	}
	if !strings.Contains(text, "Your admin account is ready") {
		t.Error("expected the heading text in the text body")
	}
	if !strings.Contains(text, "two-factor code") {
		t.Error("expected the text body to explain that login needs an emailed code")
	}
}

// Static by design: no app name, no links, nothing for an operator to
// configure. Interpolation creeping back in is what this guards.
func TestAdminAccountCreatedEmail_CarriesNoLinksOrPlaceholders(t *testing.T) {
	subject, html, text := adminAccountCreatedEmail()

	for name, body := range map[string]string{"html": html, "text": text} {
		if strings.Contains(body, "href=") || strings.Contains(body, "http://") || strings.Contains(body, "https://") {
			t.Errorf("expected no links in the %s body", name)
		}
		if strings.Contains(body, "{{") || strings.Contains(body, "%s") {
			t.Errorf("expected no template placeholders in the %s body", name)
		}
	}
	if strings.Contains(subject, "{{") || strings.Contains(subject, "%s") {
		t.Errorf("expected no template placeholders in the subject, got %q", subject)
	}
}

func TestAdminAccountCreatedEmail_IsStable(t *testing.T) {
	subject1, html1, text1 := adminAccountCreatedEmail()
	subject2, html2, text2 := adminAccountCreatedEmail()

	if subject1 != subject2 || html1 != html2 || text1 != text2 {
		t.Fatal("expected identical output across calls")
	}
	if subject1 == "" || html1 == "" || text1 == "" {
		t.Fatal("expected every part to be non-empty")
	}
}
