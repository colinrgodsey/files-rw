package filesrw

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeAccess drops a FILES_RW_ACCESS file in dir and captures the loader's warnings.
func writeAccessWithWarnings(t *testing.T, dir, content string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, AccessFileName), []byte(content), 0644); err != nil {
		t.Fatalf("writing %s: %v", AccessFileName, err)
	}
	var buf bytes.Buffer
	prev := accessWarnings
	accessWarnings = &buf
	t.Cleanup(func() { accessWarnings = prev })
	_, err := LoadAccess(dir)
	if err != nil {
		t.Fatalf("LoadAccess must not fail on a per-line problem: %v", err)
	}
	return buf.String()
}

// One over-long line is a stray paste, not a rule. It must cost only itself: the rules
// before it and after it both stay in force, because the whole file being dropped is the
// deny-all failure this loader exists to prevent.
func TestLoadAccess_OverlongLineWarnsAndKeepsOtherRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "notes"), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes", "a.md"), []byte("kept"), 0644); err != nil {
		t.Fatalf("writing note: %v", err)
	}
	long := strings.Repeat("x", MaxACLLineBytes*3)

	warn := writeAccessWithWarnings(t, dir, "w: notes/\n"+long+"\nw: notes/\n")

	if !strings.Contains(warn, "line exceeds") {
		t.Fatalf("expected an over-long line warning, got %q", warn)
	}

	acc, err := LoadAccess(dir)
	if err != nil {
		t.Fatalf("LoadAccess: %v", err)
	}
	target := filepath.Join(dir, "notes", "a.md")
	if !acc.IsWritable(target) {
		t.Errorf("the rule after the over-long line was dropped: %s not writable", target)
	}
	if _, err := acc.Resolve("notes/a.md", dir, true); err != nil {
		t.Errorf("Resolve refused a granted path after an over-long line: %v", err)
	}
}

// A file whose only content is unparsable still yields no grants rather than an error,
// so the tool keeps working for whatever the operator fixes next.
func TestLoadAccess_AllLinesOverlongYieldsNoGrants(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("y", MaxACLLineBytes+10)

	warn := writeAccessWithWarnings(t, dir, long+"\n"+long+"\n")

	if got := strings.Count(warn, "line exceeds"); got != 2 {
		t.Fatalf("expected one warning per over-long line, got %d in %q", got, warn)
	}
	acc, err := LoadAccess(dir)
	if err != nil {
		t.Fatalf("LoadAccess: %v", err)
	}
	if acc.IsWritable(filepath.Join(dir, "anything")) {
		t.Error("expected no writable roots from over-long lines alone")
	}
}

// Line numbers in the warning must match the file an operator is editing.
func TestLoadAccess_OverlongLineWarnsOnItsOwnLineNumber(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("z", MaxACLLineBytes+1)

	warn := writeAccessWithWarnings(t, dir, "w: notes/\n"+long+"\nw: notes/\n")

	if !strings.Contains(warn, "line 2") {
		t.Fatalf("expected the warning to name line 2, got %q", warn)
	}
}
