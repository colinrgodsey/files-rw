package filesrw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helperSetupAccessUncovered returns an ACL whose single rule grants a subdirectory, so the
// ACL file itself sits outside every granted root. The shared helperSetupAccess fixture
// ("w: .") cannot pin the self-read bypass: under it the ACL file is already read-covered by
// that rule, so a self-read succeeds whether or not the bypass exists.
func helperSetupAccessUncovered(t *testing.T) (string, *Access) {
	t.Helper()
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to eval symlinks for tempDir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tempDir, "granted"), 0o755); err != nil {
		t.Fatalf("failed to create granted dir: %v", err)
	}
	content := "w: granted\n"
	if err := os.WriteFile(filepath.Join(tempDir, AccessFileName), []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write access file: %v", err)
	}
	acc, err := LoadAccess(tempDir)
	if err != nil {
		t.Fatalf("LoadAccess failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, "uncovered.txt"), []byte("outside every root\n"), 0o600); err != nil {
		t.Fatalf("failed to write uncovered file: %v", err)
	}
	return tempDir, acc
}

// TestAccessFileSelfReadAllowedOutsideEveryRoot is the live repro of
// tasks/wackypub/files-rw-access-file-disagreement as a regression test: with the ACL file
// outside every granted root, reading it must still succeed, because reading the access file is
// the one always-permitted operation. README promises it ("...regardless of what rules it
// grants - only read").
func TestAccessFileSelfReadAllowedOutsideEveryRoot(t *testing.T) {
	tempDir, acc := helperSetupAccessUncovered(t)

	f, canon, err := acc.OpenFile(AccessFileName, tempDir, false, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile(%s, read) failed although self-read is always allowed: %v", AccessFileName, err)
	}
	defer f.Close()
	if canon != filepath.Join(tempDir, AccessFileName) {
		t.Errorf("canonical path = %q, want %q", canon, filepath.Join(tempDir, AccessFileName))
	}

	got, err := ReadFile(acc, AccessFileName, tempDir, 0, 0, false)
	if err != nil {
		t.Fatalf("ReadFile(%s) failed although self-read is always allowed: %v", AccessFileName, err)
	}
	if got != "w: granted\n" {
		t.Errorf("self-read content = %q, want %q", got, "w: granted\n")
	}

	// Negative control: the same read attempt on a different file that no rule covers must
	// still be denied, so the read above cannot be passing on a blanket allowance.
	if _, err := ReadFile(acc, "uncovered.txt", tempDir, 0, 0, false); err == nil {
		t.Error("expected reading an uncovered non-ACL file to be denied")
	} else if !strings.Contains(err.Error(), "not covered by any") {
		t.Errorf("expected an uncovered-rule denial, got: %v", err)
	}
}

// TestAccessFileSelfWriteDeniedOutsideEveryRoot pins the other half of the invariant on the
// same fixture: the self-write deny does not depend on a rule having been reached, so it holds
// on a path where no w: rule covers the target at all.
func TestAccessFileSelfWriteDeniedOutsideEveryRoot(t *testing.T) {
	tempDir, acc := helperSetupAccessUncovered(t)

	if err := WriteFile(acc, AccessFileName, tempDir, "hacked\n"); err == nil || !strings.Contains(err.Error(), "always denied") {
		t.Errorf("WriteFile: expected an always-denied error, got %v", err)
	}
	if err := DeleteFile(acc, AccessFileName, tempDir); err == nil || !strings.Contains(err.Error(), "always denied") {
		t.Errorf("DeleteFile: expected an always-denied error, got %v", err)
	}
	if err := Mkdir(acc, AccessFileName, tempDir, false); err == nil || !strings.Contains(err.Error(), "always denied") {
		t.Errorf("Mkdir: expected an always-denied error, got %v", err)
	}
	if _, _, err := acc.OpenFile(AccessFileName, tempDir, true, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600); err == nil || !strings.Contains(err.Error(), "always denied") {
		t.Errorf("OpenFile(write): expected an always-denied error, got %v", err)
	}

	if body, err := os.ReadFile(filepath.Join(tempDir, AccessFileName)); err != nil || string(body) != "w: granted\n" {
		t.Errorf("access file changed on disk: %q (err %v)", string(body), err)
	}
}

// TestAccessFileResolveAndOpenFileAgree is the anti-drift pin for the card's actual title.
// Resolve and OpenFile are independent entry points, so every self-related decision has to be
// the same on both; a future change to one of them that does not touch the other must land here.
func TestAccessFileResolveAndOpenFileAgree(t *testing.T) {
	tempDir, acc := helperSetupAccessUncovered(t)

	cases := []struct {
		name      string
		path      string
		needWrite bool
		wantOK    bool
	}{
		{"self read", AccessFileName, false, true},
		{"self write", AccessFileName, true, false},
		{"covered file write", filepath.Join(tempDir, "granted", "f.txt"), true, true},
		{"uncovered file read", "uncovered.txt", false, false},
		{"uncovered file write", "uncovered.txt", true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, resolveErr := acc.Resolve(tc.path, tempDir, tc.needWrite)
			flag, perm := os.O_RDONLY, os.FileMode(0)
			if tc.needWrite {
				flag, perm = os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600
			}
			f, _, openErr := acc.OpenFile(tc.path, tempDir, tc.needWrite, flag, perm)
			if f != nil {
				f.Close()
			}
			if (resolveErr == nil) != tc.wantOK {
				t.Errorf("Resolve ok = %v, want %v (err %v)", resolveErr == nil, tc.wantOK, resolveErr)
			}
			if (openErr == nil) != tc.wantOK {
				t.Errorf("OpenFile ok = %v, want %v (err %v)", openErr == nil, tc.wantOK, openErr)
			}
			if (resolveErr == nil) != (openErr == nil) {
				t.Errorf("Resolve and OpenFile disagree for %q needWrite=%v: resolve=%v open=%v", tc.path, tc.needWrite, resolveErr, openErr)
			}
		})
	}
}
