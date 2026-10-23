package migrationtool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAtlasFailureRedactsArgumentsOutputAndCause(t *testing.T) {
	// #nosec G101 -- Intentionally fake credentials verify that subprocess errors redact connection details.
	fixtureDSN := "postgres://reviewer:credential@dev.example/auth"
	cause := errors.New("runner failed while applying SELECT private_value FROM users: " + fixtureDSN)
	tool := Tool{run: func(context.Context, string, string, ...string) ([]byte, error) {
		return []byte("raw Atlas SQL: SELECT private_value FROM users\n" + fixtureDSN), cause
	}}
	_, err := tool.atlas(t.Context(), t.TempDir(), "schema", fixtureDSN)
	if err == nil || !errors.Is(err, cause) {
		t.Fatal("Atlas failure lost its original cause", err)
	}
	for _, sensitive := range []string{fixtureDSN, "private_value", "raw Atlas SQL"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatal("default Atlas error exposed subprocess details")
		}
	}
	if !strings.Contains(err.Error(), "--diagnostics") {
		t.Fatal("hidden diagnostics had no opt-in hint")
	}
}

func TestAtlasFailureUsesOnlyKnownOperationNames(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"version"}, "Atlas version failed"},
		{[]string{"migrate", "hash", "private argument"}, "Atlas migrate hash failed"},
		{[]string{"migrate", "diff", "private argument"}, "Atlas migrate diff failed"},
		{[]string{"schema", "inspect", "private argument"}, "Atlas schema inspect failed"},
		{[]string{"private argument"}, "Atlas command failed"},
	} {
		t.Run(test.want, func(t *testing.T) {
			tool := Tool{run: func(context.Context, string, string, ...string) ([]byte, error) {
				return nil, errors.New("private failure")
			}}
			_, err := tool.atlas(t.Context(), t.TempDir(), test.args...)
			if !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "--diagnostics") {
				t.Fatal("Atlas operation classification exposed arbitrary details", err)
			}
		})
	}
}

func TestAtlasDiagnosticsAreOptInAndFailureOnly(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("failure=%t", fail), func(t *testing.T) {
			var diagnostics bytes.Buffer
			cause := errors.New("failed Atlas execution")
			raw := []byte("reviewed SQL and development details\n")
			tool := Tool{Diagnostics: &diagnostics, run: func(context.Context, string, string, ...string) ([]byte, error) {
				if fail {
					return raw, cause
				}
				return raw, nil
			}}
			output, err := tool.atlas(t.Context(), t.TempDir(), "schema", "diff")
			if fail {
				if !errors.Is(fmt.Errorf("draft failed: %w", err), cause) || diagnostics.String() != string(raw) || output != nil {
					t.Fatal("opt-in diagnostics or wrapped failure were lost", err)
				}
			} else if err != nil || diagnostics.Len() != 0 || !bytes.Equal(output, raw) {
				t.Fatal("successful Atlas output was emitted as diagnostics", err)
			}
		})
	}
}

type diagnosticWriteFailure struct{ err error }

func (w diagnosticWriteFailure) Write([]byte) (int, error) { return 0, w.err }

func TestAtlasDiagnosticWriterFailureRetainsRedactedCauses(t *testing.T) {
	atlasCause := errors.New("Atlas private SQL failure")
	writerCause := errors.New("writer failed at postgres://secret@dev.example/auth")
	tool := Tool{Diagnostics: diagnosticWriteFailure{err: writerCause}, run: func(context.Context, string, string, ...string) ([]byte, error) {
		return []byte("raw private output"), atlasCause
	}}
	_, err := tool.atlas(t.Context(), t.TempDir(), "version")
	if !errors.Is(err, atlasCause) || !errors.Is(err, writerCause) || !strings.Contains(err.Error(), "diagnostic output could not be written") {
		t.Fatal("diagnostic writer failure hid an original cause", err)
	}
	for _, sensitive := range []string{"private", "postgres://", "secret"} {
		if strings.Contains(err.Error(), sensitive) {
			t.Fatal("diagnostic writer failure leaked raw details")
		}
	}
}

const atlasHelperOutput = "Atlas diagnostic: SELECT private_value FROM users; postgres://secret@dev.example/auth\n"

func TestAtlasDiagnosticHelper(_ *testing.T) {
	switch os.Getenv("GOAUTH_ATLAS_DIAGNOSTIC_HELPER") {
	case "failure":
		if _, err := fmt.Fprint(os.Stdout, atlasHelperOutput); err != nil {
			os.Exit(98)
		}
		os.Exit(17)
	case "cancel":
		if _, err := fmt.Fprint(os.Stdout, atlasHelperOutput); err != nil {
			os.Exit(98)
		}
		// #nosec G703 -- The parent test passes a readiness file in its private temporary directory.
		if err := os.WriteFile(os.Getenv("GOAUTH_ATLAS_DIAGNOSTIC_READY"), nil, 0600); err != nil {
			os.Exit(99)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func TestAtlasCommandRetainsExitStatusAndOutput(t *testing.T) {
	t.Setenv("GOAUTH_ATLAS_DIAGNOSTIC_HELPER", "failure")
	var diagnostics bytes.Buffer
	tool := Tool{AtlasPath: os.Args[0], Diagnostics: &diagnostics, run: runCommand}
	_, err := tool.atlas(t.Context(), t.TempDir(), "-test.run=^TestAtlasDiagnosticHelper$")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 17 || !strings.Contains(err.Error(), "exit status 17") || diagnostics.String() != atlasHelperOutput {
		t.Fatal("Atlas exit status or explicit diagnostics were lost", err)
	}
	if strings.Contains(err.Error(), "private_value") || strings.Contains(err.Error(), "postgres://") {
		t.Fatal("process error leaked raw Atlas output")
	}
}

func TestAtlasCancellationRetainsPartialOutputAndExitCause(t *testing.T) {
	t.Setenv("GOAUTH_ATLAS_DIAGNOSTIC_HELPER", "cancel")
	ready := filepath.Join(t.TempDir(), "ready")
	t.Setenv("GOAUTH_ATLAS_DIAGNOSTIC_READY", ready)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var diagnostics bytes.Buffer
	tool := Tool{AtlasPath: os.Args[0], Diagnostics: &diagnostics, run: runCommand}
	done := make(chan error, 1)
	directory := t.TempDir()
	go func() {
		_, err := tool.atlas(ctx, directory, "-test.run=^TestAtlasDiagnosticHelper$")
		done <- err
	}()
	finished := false
	t.Cleanup(func() {
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("canceled helper process did not stop")
			}
		}
	})
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("helper did not become ready", ctx.Err())
		}
	}
	cancel()
	select {
	case err := <-done:
		finished = true
		var exit *exec.ExitError
		if !errors.Is(fmt.Errorf("draft canceled: %w", err), context.Canceled) || !errors.As(err, &exit) || diagnostics.String() != atlasHelperOutput {
			t.Fatal("cancellation lost partial output or process/context cause", err)
		}
		if strings.Contains(err.Error(), "private_value") || strings.Contains(err.Error(), "postgres://") {
			t.Fatal("cancellation leaked raw Atlas output")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled helper process did not exit promptly")
	}
}
