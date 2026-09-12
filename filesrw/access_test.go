package filesrw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAccess_MissingFile(t *testing.T) {
	tempDir := t.TempDir()
	_, err := LoadAccess(tempDir)
	if err == nil {
		t.Fatalf("expected error when %s is missing, got nil", AccessFileName)
	}
	if !strings.Contains(err.Error(), "all file access is denied by default") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadAccess_InvalidRules(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "invalid prefix",
			content: "x: /tmp\n",
			wantErr: "invalid rule",
		},
		{
			name:    "no path",
			content: "w:\n",
			wantErr: "rule has no path",
		},
		{
			name:    "contains tilde",
			content: "w: ~/foo\n",
			wantErr: "contains \"~\"",
		},
		{
			name:    "nonexistent root",
			content: "r: /nonexistent_path_wackypub_test_dir_12345\n",
			wantErr: "failed to resolve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			accessFile := filepath.Join(tempDir, AccessFileName)
			if err := os.WriteFile(accessFile, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("failed to create access file: %v", err)
			}
			_, err := LoadAccess(tempDir)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestLoadAccess_WritableRootNeedNotExist is a regression test for a bug
// found live: a w: rule pointing at a directory that doesn't exist yet used
// to fail at LoadAccess time, making write's auto-mkdir-within-writable-root
// behavior unreachable for any brand-new output directory (the exact case
// it exists for). r: keeps the strict must-exist check.
func TestLoadAccess_WritableRootNeedNotExist(t *testing.T) {
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to eval symlinks for tempDir: %v", err)
	}

	accessContent := "w: ./notes\n"
	accessFile := filepath.Join(tempDir, AccessFileName)
	if err := os.WriteFile(accessFile, []byte(accessContent), 0o600); err != nil {
		t.Fatalf("failed to write access file: %v", err)
	}

	acc, err := LoadAccess(tempDir)
	if err != nil {
		t.Fatalf("LoadAccess failed for a not-yet-existing w: root: %v", err)
	}

	canon, err := acc.Resolve("notes/new_file.txt", tempDir, true)
	if err != nil {
		t.Fatalf("expected write access to a new file under a not-yet-existing w: root, got: %v", err)
	}
	expected := filepath.Join(tempDir, "notes", "new_file.txt")
	if canon != expected {
		t.Errorf("resolved path %q != expected %q", canon, expected)
	}
}

func TestAccess_Resolve(t *testing.T) {
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to eval symlinks for tempDir: %v", err)
	}

	readOnlyDir := filepath.Join(tempDir, "readonly")
	readWriteDir := filepath.Join(tempDir, "readwrite")
	outsideDir := filepath.Join(tempDir, "outside")

	for _, d := range []string{readOnlyDir, readWriteDir, outsideDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("failed to create dir %s: %v", d, err)
		}
	}

	accessContent := strings.Join([]string{
		"# Comment line",
		"",
		"r: readonly",
		"w: readwrite",
	}, "\n")

	accessFile := filepath.Join(tempDir, AccessFileName)
	if err := os.WriteFile(accessFile, []byte(accessContent), 0o600); err != nil {
		t.Fatalf("failed to write access file: %v", err)
	}

	acc, err := LoadAccess(tempDir)
	if err != nil {
		t.Fatalf("LoadAccess failed: %v", err)
	}

	// 1. FILES_RW_ACCESS itself: read always allowed (self-introspection),
	// write always denied (mutating it is the actual privilege-escalation
	// risk), regardless of any rule that would otherwise cover it.
	accessFilePath := filepath.Join(tempDir, AccessFileName)
	canonAccess, err := acc.Resolve(AccessFileName, tempDir, false)
	if err != nil {
		t.Errorf("expected FILES_RW_ACCESS to be readable, got err: %v", err)
	}
	if canonAccess != accessFilePath {
		t.Errorf("resolved path %q != expected %q", canonAccess, accessFilePath)
	}
	_, err = acc.Resolve(AccessFileName, tempDir, true)
	if err == nil || !strings.Contains(err.Error(), "always denied") {
		t.Errorf("expected FILES_RW_ACCESS write to be denied, got err: %v", err)
	}

	// 2. Read existing file in read-only dir
	roFile := filepath.Join(readOnlyDir, "test.txt")
	if err := os.WriteFile(roFile, []byte("hello"), 0o600); err != nil {
		t.Fatalf("failed to create roFile: %v", err)
	}
	canon, err := acc.Resolve("readonly/test.txt", tempDir, false)
	if err != nil {
		t.Errorf("failed to resolve read access for roFile: %v", err)
	}
	if canon != roFile {
		t.Errorf("resolved path %q != expected %q", canon, roFile)
	}

	// 3. Write access to read-only dir denied
	_, err = acc.Resolve("readonly/test.txt", tempDir, true)
	if err == nil {
		t.Errorf("expected write error for read-only dir, got nil")
	}

	// 4. Write access to readwrite dir allowed (even for new file)
	newFileRel := "readwrite/new_file.txt"
	canonNew, err := acc.Resolve(newFileRel, tempDir, true)
	if err != nil {
		t.Errorf("expected write access for new file in readwrite dir, got err: %v", err)
	}
	expectedNew := filepath.Join(readWriteDir, "new_file.txt")
	if canonNew != expectedNew {
		t.Errorf("resolved path %q != expected %q", canonNew, expectedNew)
	}

	// 5. Access to outside dir denied
	_, err = acc.Resolve("outside/test.txt", tempDir, false)
	if err == nil {
		t.Errorf("expected read error for outside dir, got nil")
	}

	// 6. Boundary check: readwrite-secret must not match readwrite
	rwSecret := filepath.Join(tempDir, "readwrite-secret")
	if err := os.MkdirAll(rwSecret, 0o755); err != nil {
		t.Fatalf("failed to create rwSecret dir: %v", err)
	}
	_, err = acc.Resolve("readwrite-secret", tempDir, false)
	if err == nil {
		t.Errorf("expected error for boundary prefix collision, got nil")
	}

	// 7. Symlink inside readwrite pointing to outside dir must be denied
	symlinkPath := filepath.Join(readWriteDir, "escape_link")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}
	_, err = acc.Resolve("readwrite/escape_link/secret.txt", tempDir, false)
	if err == nil {
		t.Errorf("expected escape symlink to be denied, got nil")
	}
}

func TestAccess_SelfReadBypass(t *testing.T) {
	tempDir, _ := filepath.EvalSymlinks(t.TempDir())
	repoDir := filepath.Join(tempDir, "repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("failed to create repoDir: %v", err)
	}

	accessFile := filepath.Join(tempDir, AccessFileName)
	// Use a subdirectory rule that does NOT cover the parent directory.
	// This ensures FILES_RW_ACCESS is NOT in a readable root.
	os.WriteFile(accessFile, []byte("w: repo\n"), 0o600)

	acc, _ := LoadAccess(tempDir)

	// 1. Verify Resolve works (due to bypass)
	canon, err := acc.Resolve(AccessFileName, tempDir, false)
	if err != nil {
		t.Errorf("Resolve should allow self-read via bypass, got err: %v", err)
	}
	if canon != accessFile {
		t.Errorf("expected %s, got %s", accessFile, canon)
	}

	// 2. Verify OpenFile works (due to bypass)
	f, canon, err := acc.OpenFile(AccessFileName, tempDir, false, os.O_RDONLY, 0)
	if err != nil {
		t.Errorf("OpenFile should allow self-read via bypass, got err: %v", err)
	} else {
		f.Close()
		if canon != accessFile {
			t.Errorf("expected %s, got %s", accessFile, canon)
		}
	}

	// 3. Verify Write Denial
	_, err = acc.Resolve(AccessFileName, tempDir, true)
	if err == nil || !strings.Contains(err.Error(), "always denied") {
		t.Errorf("Resolve should deny self-write, got err: %v", err)
	}

	_, _, err = acc.OpenFile(AccessFileName, tempDir, true, os.O_WRONLY, 0)
	if err == nil || !strings.Contains(err.Error(), "always denied") {
		t.Errorf("OpenFile should deny self-write, got err: %v", err)
	}
}

func TestAccess_SelfReadBypass_NegativeControl(t *testing.T) {
	tempDir, _ := filepath.EvalSymlinks(t.TempDir())
	repoDir := filepath.Join(tempDir, "repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatalf("failed to create repoDir: %v", err)
	}
	secretDir := filepath.Join(tempDir, "secret")
	if err := os.MkdirAll(secretDir, 0755); err != nil {
		t.Fatalf("failed to create secretDir: %v", err)
	}

	accessFile := filepath.Join(tempDir, AccessFileName)
	// Rule: only allows writing to 'repo'.
	// 'secret/' is NOT covered by any rule.
	os.WriteFile(accessFile, []byte("w: repo\n"), 0o600)

	acc, _ := LoadAccess(tempDir)

	// Attempt to read a file in the secret directory. 
	// It should be denied because it's not in any rule.
	// (We must ensure the file exists or that the access check happens BEFORE the open)
	target := filepath.Join(secretDir, "foo")
	os.WriteFile(target, []byte("data"), 0o600)

	_, _, err := acc.OpenFile(target, tempDir, false, os.O_RDONLY, 0)
	if err == nil {
		t.Error("expected access denied error for uncovered directory, got nil")
	} else if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected access denied error, got: %v", err)
	}
}
