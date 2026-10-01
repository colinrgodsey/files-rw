package filesrw

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := accessWarnings
	accessWarnings = buf
	t.Cleanup(func() { accessWarnings = prev })
	return buf
}

func writeACL(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, AccessFileName), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", AccessFileName, err)
	}
}

func mustDir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	return path
}

// A single non-existent path used to revoke every other grant in the file. An ACL is a
// grant list rather than a directory listing, so a not-yet-created file is a valid target
// and creation through it is the point of the entry.
func TestLoadAccess_NonexistentWriteRootKeepsOtherGrants(t *testing.T) {
	dir := t.TempDir()
	work := mustDir(t, filepath.Join(dir, "work"))
	warnings := captureWarnings(t)
	writeACL(t, dir, "w: "+filepath.Join(dir, "critique.md")+"\nw: "+work+"\n")

	acc, err := LoadAccess(dir)
	if err != nil {
		t.Fatalf("a non-existent w: path must not fail the whole ACL: %v", err)
	}
	got := warnings.String()
	if !strings.Contains(got, "critique.md") {
		t.Errorf("expected a warning naming the offending path, got %q", got)
	}
	if !strings.Contains(got, "line 1") {
		t.Errorf("expected the warning to cite the line number, got %q", got)
	}

	if _, err := acc.Resolve(filepath.Join(work, "a.txt"), dir, true); err != nil {
		t.Errorf("the valid w: root must stay enforced, got %v", err)
	}
	if _, err := acc.Resolve(filepath.Join(dir, "..", "outside.txt"), dir, true); err == nil {
		t.Error("a path outside every root must stay denied")
	}

	if err := WriteFile(acc, "critique.md", dir, "first draft"); err != nil {
		t.Fatalf("creating a file through a not-yet-existing w: root: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "critique.md"))
	if err != nil || string(data) != "first draft" {
		t.Errorf("created file reads %q, err %v", data, err)
	}
}

func TestLoadAccess_NonexistentWriteRootAllowsNestedCreation(t *testing.T) {
	dir := t.TempDir()
	captureWarnings(t)
	writeACL(t, dir, "w: "+filepath.Join(dir, "later")+"\n")

	acc, err := LoadAccess(dir)
	if err != nil {
		t.Fatalf("a non-existent w: prefix must not fail the ACL: %v", err)
	}
	if err := WriteFile(acc, filepath.Join("later", "deep", "note.md"), dir, "body"); err != nil {
		t.Fatalf("creation under a not-yet-existing prefix: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "later", "deep", "note.md")); err != nil {
		t.Errorf("expected the nested file to exist: %v", err)
	}
}

// The opposite failure mode: malformed lines were swallowed, so an operator got no hint
// that half of the file was not in effect. Both classes now warn and keep going.
func TestLoadAccess_MalformedLinesWarnAndSkip(t *testing.T) {
	dir := t.TempDir()
	work := mustDir(t, filepath.Join(dir, "work"))
	warnings := captureWarnings(t)
	writeACL(t, dir, "x: /tmp\nw:\nw: ~/nope\nw: "+work+"\n")

	acc, err := LoadAccess(dir)
	if err != nil {
		t.Fatalf("malformed rules must be skipped, not fatal: %v", err)
	}
	got := warnings.String()
	if n := strings.Count(got, "rule ignored"); n != 3 {
		t.Errorf("expected 3 warnings, got %d in %q", n, got)
	}
	for _, want := range []string{"line 1", "line 2", "line 3"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected a warning citing %s, got %q", want, got)
		}
	}
	if _, err := acc.Resolve(filepath.Join(work, "a.txt"), dir, true); err != nil {
		t.Errorf("the well-formed rule must stay enforced, got %v", err)
	}
	if strings.Contains(got, "does not exist yet") {
		t.Errorf("an unresolvable rule must report only that it was ignored, not that it is pending: %q", got)
	}
}

// A read root for a path that does not exist yet is inert rather than fatal, and stays in
// effect once the path appears.
func TestLoadAccess_NonexistentReadRootIsRetained(t *testing.T) {
	dir := t.TempDir()
	warnings := captureWarnings(t)
	missing := filepath.Join(dir, "later-read.md")
	writeACL(t, dir, "r: "+missing+"\n")

	acc, err := LoadAccess(dir)
	if err != nil {
		t.Fatalf("a non-existent r: path must not fail the ACL: %v", err)
	}
	if !strings.Contains(warnings.String(), "later-read.md") {
		t.Errorf("expected a warning naming the unreadable path, got %q", warnings.String())
	}

	if err := os.WriteFile(missing, []byte("now it exists"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	content, err := ReadFile(acc, missing, dir, 0, 0, false)
	if err != nil {
		t.Fatalf("the retained r: root should permit the read, got %v", err)
	}
	if content != "now it exists" {
		t.Errorf("read %q", content)
	}
}

// Whole-file problems still deny everything, which is the only fail-closed case left.
func TestLoadAccess_MissingFileStillDeniesAll(t *testing.T) {
	dir := t.TempDir()
	captureWarnings(t)
	if _, err := LoadAccess(dir); err == nil {
		t.Fatal("expected an error when there is no ACL file at all")
	}
}
