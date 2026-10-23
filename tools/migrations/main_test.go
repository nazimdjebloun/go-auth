package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaintainerDiagnosticsFlag(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	const raw = "Atlas CLI detail: SELECT private_value FROM users; postgres://secret@dev.example/auth"
	atlas := filepath.Join(t.TempDir(), "atlas")
	// #nosec G306 -- This private test fixture is an executable shell script.
	if err := os.WriteFile(atlas, []byte("#!/bin/sh\nprintf '%s\\n' '"+raw+"' >&2\nexit 17\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"", "--diagnostics", "--diagnostics=false"} {
		t.Run("flag="+flag, func(t *testing.T) {
			cmd := newCommand()
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			args := []string{"draft", "--root", root, "--atlas", atlas, "--driver", "sqlite", "--release", "v99.0.0", "--out", filepath.Join(t.TempDir(), "draft")}
			if flag != "" {
				args = append(args, flag)
			}
			cmd.SetArgs(args)
			err := cmd.ExecuteContext(t.Context())
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 17 {
				t.Fatal("CLI did not preserve the failed Atlas exit", err)
			}
			if stdout.Len() != 0 || strings.Contains(err.Error(), "private_value") || strings.Contains(err.Error(), "postgres://") || strings.Contains(err.Error(), atlas) {
				t.Fatal("CLI default output leaked Atlas details")
			}
			if flag == "--diagnostics" {
				if stderr.String() != raw+"\n" {
					t.Fatal("explicit CLI diagnostics did not reach stderr")
				}
			} else if stderr.Len() != 0 {
				t.Fatal("CLI emitted diagnostics without opt-in")
			}
		})
	}
}
