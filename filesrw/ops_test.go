package filesrw

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func helperSetupAccess(t *testing.T) (string, *Access) {
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to eval symlinks for tempDir: %v", err)
	}

	accessContent := "w: .\n"
	accessFile := filepath.Join(tempDir, AccessFileName)
	if err := os.WriteFile(accessFile, []byte(accessContent), 0o600); err != nil {
		t.Fatalf("failed to write access file: %v", err)
	}

	acc, err := LoadAccess(tempDir)
	if err != nil {
		t.Fatalf("LoadAccess failed: %v", err)
	}
	return tempDir, acc
}

func TestReadFile(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)
	filePath := filepath.Join(tempDir, "sample.txt")
	content := "line 1\nline 2\nline 3\nline 4\n"
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write sample file: %v", err)
	}

	// 1. Default unnumbered raw read
	rawOut, err := ReadFile(acc, "sample.txt", tempDir, 0, 0, false)
	if err != nil {
		t.Fatalf("ReadFile raw failed: %v", err)
	}
	if rawOut != content {
		t.Errorf("got %q, expected %q", rawOut, content)
	}

	// 2. Numbered read (cat -n style: %6d\t%s)
	numberedOut, err := ReadFile(acc, "sample.txt", tempDir, 0, 0, true)
	if err != nil {
		t.Fatalf("ReadFile numbered failed: %v", err)
	}
	expectedNumbered := "     1\tline 1\n     2\tline 2\n     3\tline 3\n     4\tline 4\n"
	if numberedOut != expectedNumbered {
		t.Errorf("got %q, expected %q", numberedOut, expectedNumbered)
	}

	// 3. Line range [2, 3] unnumbered
	outRange, err := ReadFile(acc, "sample.txt", tempDir, 2, 3, false)
	if err != nil {
		t.Fatalf("ReadFile range failed: %v", err)
	}
	expectedRange := "line 2\nline 3\n"
	if outRange != expectedRange {
		t.Errorf("got %q, expected %q", outRange, expectedRange)
	}

	// 4. Hard read size limit (> 200KB) error
	largePath := filepath.Join(tempDir, "large.txt")
	largeData := make([]byte, MaxReadSizeBytes+1024)
	for i := range largeData {
		largeData[i] = 'a'
	}
	if err := os.WriteFile(largePath, largeData, 0o600); err != nil {
		t.Fatalf("failed to write large file: %v", err)
	}
	_, err = ReadFile(acc, "large.txt", tempDir, 0, 0, false)
	if err == nil || !strings.Contains(err.Error(), "exceeds the 204800 byte read limit") {
		t.Errorf("expected read size cap error, got %v", err)
	}

	// 5. Binary file read rejection
	binPath := filepath.Join(tempDir, "sample.bin")
	binContent := []byte{'h', 'e', 'l', 'l', 'o', 0, 'w', 'o', 'r', 'l', 'd'}
	if err := os.WriteFile(binPath, binContent, 0o600); err != nil {
		t.Fatalf("failed to write binary file: %v", err)
	}
	_, err = ReadFile(acc, "sample.bin", tempDir, 0, 0, false)
	if err == nil || !strings.Contains(err.Error(), "binary file") {
		t.Errorf("expected binary file error, got %v", err)
	}

	// 6. Reading FILES_RW_ACCESS itself is allowed (D24 Addendum)
	accFileContent, err := ReadFile(acc, AccessFileName, tempDir, 0, 0, false)
	if err != nil {
		t.Fatalf("expected reading %s to succeed, got %v", AccessFileName, err)
	}
	if accFileContent != "w: .\n" {
		t.Errorf("got %q, expected %q", accFileContent, "w: .\n")
	}
}

func TestCatFile(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)

	// 1. Cat binary file (must succeed, bypassing isBinary)
	binPath := filepath.Join(tempDir, "sample.bin")
	binContent := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 1, 2, 3}
	if err := os.WriteFile(binPath, binContent, 0o600); err != nil {
		t.Fatalf("failed to write binary file: %v", err)
	}

	var buf strings.Builder
	if err := CatFile(acc, "sample.bin", tempDir, &buf); err != nil {
		t.Fatalf("CatFile on binary file failed: %v", err)
	}
	if buf.String() != string(binContent) {
		t.Errorf("got %q, expected %q", buf.String(), string(binContent))
	}

	// 2. Cat text file
	txtPath := filepath.Join(tempDir, "hello.txt")
	if err := os.WriteFile(txtPath, []byte("hello world"), 0o600); err != nil {
		t.Fatalf("failed to write text file: %v", err)
	}
	buf.Reset()
	if err := CatFile(acc, "hello.txt", tempDir, &buf); err != nil {
		t.Fatalf("CatFile on text file failed: %v", err)
	}
	if buf.String() != "hello world" {
		t.Errorf("got %q, expected %q", buf.String(), "hello world")
	}

	// 3. Cat rejects file exceeding 30MB limit
	// (Create a sparse or stat-checked mock file or test the limit check)
	hugePath := filepath.Join(tempDir, "huge.bin")
	hugeFile, err := os.Create(hugePath)
	if err != nil {
		t.Fatalf("failed to create huge file: %v", err)
	}
	// Truncate to 31MB without writing 31MB to disk
	if err := hugeFile.Truncate(int64(MaxCatSizeBytes + 1024)); err != nil {
		_ = hugeFile.Close()
		t.Fatalf("failed to truncate huge file: %v", err)
	}
	_ = hugeFile.Close()

	buf.Reset()
	err = CatFile(acc, "huge.bin", tempDir, &buf)
	if err == nil || !strings.Contains(err.Error(), "exceeds the 31457280 byte cat limit") {
		t.Fatalf("expected cat limit error, got: %v", err)
	}
}

func TestHardlinkReadBypassRejection(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)

	// Create an external secret file outside the allowed root
	outsideDir := t.TempDir()
	secretFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("super_secret_key"), 0o600); err != nil {
		t.Fatalf("failed to create secret file: %v", err)
	}

	// Hardlink the external secret file into allowed root
	hlPath := filepath.Join(tempDir, "hl_secret.txt")
	if err := os.Link(secretFile, hlPath); err != nil {
		t.Fatalf("failed to create hardlink: %v", err)
	}

	// Attempting to read hardlink must be rejected!
	_, err := ReadFile(acc, "hl_secret.txt", tempDir, 0, 0, false)
	if err == nil || !strings.Contains(err.Error(), "hardlink target has") {
		t.Errorf("expected cross-root hardlink read rejection, got: %v", err)
	}
}

func TestWriteFile(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)
	nestedRel := filepath.Join("sub", "dir", "output.txt")

	content := "hello world\n"
	if err := WriteFile(acc, nestedRel, tempDir, content); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	fullPath := filepath.Join(tempDir, nestedRel)
	readBack, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("failed to read back written file: %v", err)
	}
	if string(readBack) != content {
		t.Errorf("got %q, expected %q", string(readBack), content)
	}

	// Writing to FILES_RW_ACCESS itself must be denied
	err = WriteFile(acc, AccessFileName, tempDir, "hacked\n")
	if err == nil || !strings.Contains(err.Error(), "always denied") {
		t.Errorf("expected writing to FILES_RW_ACCESS to be denied, got %v", err)
	}
}

func TestCopyFile(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)
	src := "src.txt"
	dst := filepath.Join("sub", "dst.txt")
	content := "copy test bytes\n"

	if err := os.WriteFile(filepath.Join(tempDir, src), []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write src: %v", err)
	}

	if err := CopyFile(acc, src, dst, tempDir); err != nil {
		t.Fatalf("CopyFile failed: %v", err)
	}

	readBack, err := os.ReadFile(filepath.Join(tempDir, dst))
	if err != nil {
		t.Fatalf("failed to read dst: %v", err)
	}
	if string(readBack) != content {
		t.Errorf("got %q, expected %q", string(readBack), content)
	}
}

func TestMoveFile(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)
	src := "move_src.txt"
	dst := filepath.Join("sub", "move_dst.txt")
	content := "move test bytes\n"

	if err := os.WriteFile(filepath.Join(tempDir, src), []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write src: %v", err)
	}

	if err := MoveFile(acc, src, dst, tempDir); err != nil {
		t.Fatalf("MoveFile failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tempDir, src)); !os.IsNotExist(err) {
		t.Errorf("expected source file to be removed after move")
	}

	readBack, err := os.ReadFile(filepath.Join(tempDir, dst))
	if err != nil {
		t.Fatalf("failed to read dst: %v", err)
	}
	if string(readBack) != content {
		t.Errorf("got %q, expected %q", string(readBack), content)
	}
}

func TestDeleteFile(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)
	target := "delete_me.txt"
	fullPath := filepath.Join(tempDir, target)
	if err := os.WriteFile(fullPath, []byte("temp"), 0o600); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}

	if err := DeleteFile(acc, target, tempDir); err != nil {
		t.Fatalf("DeleteFile failed: %v", err)
	}

	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		t.Errorf("expected file to be deleted")
	}
}

func TestEditFile(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)
	filePath := "edit.txt"
	fullPath := filepath.Join(tempDir, filePath)

	initial := "foo bar foo baz\n"
	if err := os.WriteFile(fullPath, []byte(initial), 0o600); err != nil {
		t.Fatalf("failed to write edit file: %v", err)
	}

	// Empty old string
	if err := EditFile(acc, filePath, tempDir, "", "new", false); err == nil {
		t.Errorf("expected error for empty old string, got nil")
	}

	// Zero match
	if err := EditFile(acc, filePath, tempDir, "nonexistent", "new", false); err == nil {
		t.Errorf("expected error for zero matches, got nil")
	}

	// Multiple matches without replaceAll
	if err := EditFile(acc, filePath, tempDir, "foo", "new", false); err == nil {
		t.Errorf("expected error for multiple matches without replaceAll, got nil")
	}

	// Multiple matches with replaceAll
	if err := EditFile(acc, filePath, tempDir, "foo", "QUX", true); err != nil {
		t.Fatalf("EditFile with replaceAll failed: %v", err)
	}
	readBack, _ := os.ReadFile(fullPath)
	if string(readBack) != "QUX bar QUX baz\n" {
		t.Errorf("got %q, expected QUX bar QUX baz", string(readBack))
	}

	// Single match replacement
	if err := EditFile(acc, filePath, tempDir, "bar", "FOO", false); err != nil {
		t.Fatalf("EditFile single match failed: %v", err)
	}
	readBackSingle, _ := os.ReadFile(fullPath)
	if string(readBackSingle) != "QUX FOO QUX baz\n" {
		t.Errorf("got %q, expected QUX FOO QUX baz", string(readBackSingle))
	}
}

func TestPatchFile(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)
	filePath := "patch_target.txt"
	fullPath := filepath.Join(tempDir, filePath)
	if err := os.WriteFile(fullPath, []byte("line 1\nline 2\nline 3\n"), 0o600); err != nil {
		t.Fatalf("failed to write patch target: %v", err)
	}

	// Non-unified diff rejected
	if err := PatchFile(acc, filePath, tempDir, "invalid diff format"); err == nil {
		t.Errorf("expected non-unified diff to be rejected, got nil")
	}

	// Valid unified diff
	diff := strings.Join([]string{
		"--- patch_target.txt",
		"+++ patch_target.txt",
		"@@ -1,3 +1,3 @@",
		" line 1",
		"-line 2",
		"+line TWO",
		" line 3",
	}, "\n") + "\n"

	if err := PatchFile(acc, filePath, tempDir, diff); err != nil {
		t.Fatalf("PatchFile failed: %v", err)
	}

	readBack, _ := os.ReadFile(fullPath)
	expected := "line 1\nline TWO\nline 3\n"
	if string(readBack) != expected {
		t.Errorf("got %q, expected %q", string(readBack), expected)
	}
}

func TestListDir(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)
	file1 := filepath.Join(tempDir, "alpha.txt")
	if err := os.WriteFile(file1, []byte("content"), 0o600); err != nil {
		t.Fatalf("failed to write alpha: %v", err)
	}

	out, err := ListDir(acc, ".", tempDir, false, false, false, false)
	if err != nil {
		t.Fatalf("ListDir failed: %v", err)
	}
	if !strings.Contains(out, "alpha.txt") {
		t.Errorf("expected output to contain alpha.txt, got %q", out)
	}
}

func TestTailFile(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)
	filePath := filepath.Join(tempDir, "tail.txt")
	content := "line 1\nline 2\nline 3\nline 4\nline 5\n"
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write tail file: %v", err)
	}

	// 1. Unnumbered tail -n 2
	tailOut, err := TailFile(acc, "tail.txt", tempDir, 2, false)
	if err != nil {
		t.Fatalf("TailFile failed: %v", err)
	}
	expectedTail := "Total lines: 5\nline 4\nline 5\n"
	if tailOut != expectedTail {
		t.Errorf("got %q, expected %q", tailOut, expectedTail)
	}

	// 2. Numbered tail -n 2
	numberedTail, err := TailFile(acc, "tail.txt", tempDir, 2, true)
	if err != nil {
		t.Fatalf("TailFile numbered failed: %v", err)
	}
	expectedNumberedTail := "Total lines: 5\n     4\tline 4\n     5\tline 5\n"
	if numberedTail != expectedNumberedTail {
		t.Errorf("got %q, expected %q", numberedTail, expectedNumberedTail)
	}
}

func TestAppendFile(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)
	filePath := filepath.Join(tempDir, "append.txt")
	initial := "line 1\n"
	if err := os.WriteFile(filePath, []byte(initial), 0o600); err != nil {
		t.Fatalf("failed to write initial file: %v", err)
	}

	appendData := "line 2\nline 3\n"
	if err := AppendFile(acc, "append.txt", tempDir, appendData); err != nil {
		t.Fatalf("AppendFile failed: %v", err)
	}

	readBack, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read back appended file: %v", err)
	}
	expected := "line 1\nline 2\nline 3\n"
	if string(readBack) != expected {
		t.Errorf("got %q, expected %q", string(readBack), expected)
	}
}

func helperSetupMultiRootAccess(t *testing.T) (string, *Access, string, string, string) {
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to eval symlinks for tempDir: %v", err)
	}

	writableDir := filepath.Join(tempDir, "writable")
	readonlyDir := filepath.Join(tempDir, "readonly")
	outsideDir := filepath.Join(tempDir, "outside")

	for _, d := range []string{writableDir, readonlyDir, outsideDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("failed to create dir %s: %v", d, err)
		}
	}

	accessContent := strings.Join([]string{
		"w: writable",
		"r: readonly",
	}, "\n") + "\n"

	accessFile := filepath.Join(tempDir, AccessFileName)
	if err := os.WriteFile(accessFile, []byte(accessContent), 0o600); err != nil {
		t.Fatalf("failed to write access file: %v", err)
	}

	acc, err := LoadAccess(tempDir)
	if err != nil {
		t.Fatalf("LoadAccess failed: %v", err)
	}
	return tempDir, acc, writableDir, readonlyDir, outsideDir
}

// (a) symlink create succeeds with write@source + read@target
func TestSymlink_Create_Success(t *testing.T) {
	tempDir, acc, writableDir, readonlyDir, _ := helperSetupMultiRootAccess(t)

	targetFile := filepath.Join(readonlyDir, "target.txt")
	if err := os.WriteFile(targetFile, []byte("target payload\n"), 0o600); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}

	linkRel := "writable/link.txt"
	targetRel := "../readonly/target.txt"
	if err := SymlinkFile(acc, linkRel, targetRel, tempDir, false); err != nil {
		t.Fatalf("SymlinkFile failed: %v", err)
	}

	linkPath := filepath.Join(writableDir, "link.txt")
	gotTarget, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("failed to readlink: %v", err)
	}
	if gotTarget != targetRel {
		t.Errorf("readlink = %q, want %q", gotTarget, targetRel)
	}

	readContent, err := ReadFile(acc, linkRel, tempDir, 0, 0, false)
	if err != nil {
		t.Fatalf("ReadFile through symlink failed: %v", err)
	}
	if readContent != "target payload\n" {
		t.Errorf("ReadFile = %q, want %q", readContent, "target payload\n")
	}
}

// (b) create DENIED when caller lacks read coverage at the target (even if source writable)
func TestSymlink_Create_Denied_NoReadCoverage(t *testing.T) {
	tempDir, acc, writableDir, _, outsideDir := helperSetupMultiRootAccess(t)

	secretFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("super_secret\n"), 0o600); err != nil {
		t.Fatalf("failed to write secret: %v", err)
	}

	// Relative target outside granted roots
	err := SymlinkFile(acc, "writable/leak_rel.txt", "../outside/secret.txt", tempDir, false)
	if err == nil {
		t.Fatal("expected symlink create to be denied when target lacks read coverage, got nil")
	}
	if !strings.Contains(err.Error(), "read access denied") {
		t.Errorf("unexpected error: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(writableDir, "leak_rel.txt")); !os.IsNotExist(err) {
		t.Error("link should not have been created on failure")
	}

	// Absolute target outside granted roots
	err = SymlinkFile(acc, "writable/leak_abs.txt", secretFile, tempDir, false)
	if err == nil {
		t.Fatal("expected symlink create to be denied with absolute outside target, got nil")
	}
	if !strings.Contains(err.Error(), "read access denied") {
		t.Errorf("unexpected error: %v", err)
	}
}

// (c) dangling forward-link creation inside a read-covered root still allowed (coverage-based)
func TestSymlink_Create_DanglingCoverageBased(t *testing.T) {
	tempDir, acc, writableDir, readonlyDir, _ := helperSetupMultiRootAccess(t)

	// Target in readonly root does not exist yet (runtime.json forward creation pattern)
	futureFile := filepath.Join(readonlyDir, "future.json")
	if _, err := os.Stat(futureFile); !os.IsNotExist(err) {
		t.Fatal("future target must not exist for this test")
	}

	err := SymlinkFile(acc, "writable/forward.json", "../readonly/future.json", tempDir, false)
	if err != nil {
		t.Fatalf("expected forward link creation inside read-covered root to succeed, got: %v", err)
	}

	linkPath := filepath.Join(writableDir, "forward.json")
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("failed to read created link: %v", err)
	}
	if target != "../readonly/future.json" {
		t.Errorf("got target %q, want %q", target, "../readonly/future.json")
	}
}

// (d) list shows type/target/resolved for a symlink, dangling and blocked states included (blocked value only ever "blocked", never the path)
func TestListDir_SymlinkStatesJSON(t *testing.T) {
	tempDir, acc, writableDir, readonlyDir, outsideDir := helperSetupMultiRootAccess(t)

	// 1. Present and reachable
	realTarget := filepath.Join(readonlyDir, "present.txt")
	if err := os.WriteFile(realTarget, []byte("ok"), 0o600); err != nil {
		t.Fatalf("failed to write present target: %v", err)
	}
	if err := SymlinkFile(acc, "writable/link_reachable", "../readonly/present.txt", tempDir, false); err != nil {
		t.Fatalf("failed to create reachable link: %v", err)
	}

	// 2. Missing/dangling inside read-covered root
	if err := SymlinkFile(acc, "writable/link_dangling", "../readonly/missing.txt", tempDir, false); err != nil {
		t.Fatalf("failed to create dangling link: %v", err)
	}

	// 3. Blocked: points outside granted roots (created directly on disk)
	secretPath := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("shh"), 0o600); err != nil {
		t.Fatalf("failed to write secret: %v", err)
	}
	if err := os.Symlink(secretPath, filepath.Join(writableDir, "link_blocked")); err != nil {
		t.Fatalf("failed to create blocked link: %v", err)
	}

	out, err := ListDir(acc, "writable", tempDir, false, false, false, true)
	if err != nil {
		t.Fatalf("ListDir asJSON failed: %v", err)
	}

	var entries []ListEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("failed to unmarshal ListDir JSON output %q: %v", out, err)
	}

	byName := make(map[string]ListEntry)
	for _, e := range entries {
		byName[e.Name] = e
	}

	// Check reachable
	reach, ok := byName["link_reachable"]
	if !ok {
		t.Fatal("link_reachable entry not found in list")
	}
	if reach.Type != "symlink" {
		t.Errorf("link_reachable type = %q, want symlink", reach.Type)
	}
	if reach.Target != "../readonly/present.txt" {
		t.Errorf("link_reachable target = %q, want ../readonly/present.txt", reach.Target)
	}
	if reach.Resolved != realTarget {
		t.Errorf("link_reachable resolved = %q, want %q", reach.Resolved, realTarget)
	}

	// Check dangling
	dang, ok := byName["link_dangling"]
	if !ok {
		t.Fatal("link_dangling entry not found in list")
	}
	if dang.Type != "symlink" {
		t.Errorf("link_dangling type = %q, want symlink", dang.Type)
	}
	if dang.Target != "../readonly/missing.txt" {
		t.Errorf("link_dangling target = %q, want ../readonly/missing.txt", dang.Target)
	}
	if dang.Resolved != "dangling" {
		t.Errorf("link_dangling resolved = %q, want dangling", dang.Resolved)
	}

	// Check blocked
	block, ok := byName["link_blocked"]
	if !ok {
		t.Fatal("link_blocked entry not found in list")
	}
	if block.Type != "symlink" {
		t.Errorf("link_blocked type = %q, want symlink", block.Type)
	}
	if block.Target != secretPath {
		t.Errorf("link_blocked target = %q, want %q", block.Target, secretPath)
	}
	if block.Resolved != "blocked" {
		t.Errorf("link_blocked resolved = %q, want blocked", block.Resolved)
	}
	if strings.Contains(block.Resolved, secretPath) || strings.Contains(block.Resolved, "outside") {
		t.Errorf("blocked state leaked path: %q", block.Resolved)
	}
}

// (e) read/write/patch/cat through a symlink follows transparently incl. the existing deny-outside-root case
func TestSymlink_DereferenceOps(t *testing.T) {
	tempDir, acc, writableDir, _, outsideDir := helperSetupMultiRootAccess(t)

	targetPath := filepath.Join(writableDir, "real_target.txt")
	initial := "line 1\nline 2\nline 3\n"
	if err := os.WriteFile(targetPath, []byte(initial), 0o600); err != nil {
		t.Fatalf("failed to write initial target: %v", err)
	}

	linkRel := "writable/sym_link.txt"
	if err := SymlinkFile(acc, linkRel, "real_target.txt", tempDir, false); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// 1. Read through symlink
	readOut, err := ReadFile(acc, linkRel, tempDir, 0, 0, false)
	if err != nil {
		t.Fatalf("ReadFile through symlink failed: %v", err)
	}
	if readOut != initial {
		t.Errorf("read = %q, want %q", readOut, initial)
	}

	// 2. Cat through symlink
	var buf strings.Builder
	if err := CatFile(acc, linkRel, tempDir, &buf); err != nil {
		t.Fatalf("CatFile through symlink failed: %v", err)
	}
	if buf.String() != initial {
		t.Errorf("cat = %q, want %q", buf.String(), initial)
	}

	// 3. Write through symlink
	newContent := "written via symlink\n"
	if err := WriteFile(acc, linkRel, tempDir, newContent); err != nil {
		t.Fatalf("WriteFile through symlink failed: %v", err)
	}
	targetBytes, _ := os.ReadFile(targetPath)
	if string(targetBytes) != newContent {
		t.Errorf("target file content = %q, want %q", string(targetBytes), newContent)
	}
	fi, err := os.Lstat(filepath.Join(writableDir, "sym_link.txt"))
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("sym_link.txt should still be a symlink")
	}

	// 4. Patch through symlink
	diff := strings.Join([]string{
		"--- real_target.txt",
		"+++ real_target.txt",
		"@@ -1,1 +1,1 @@",
		"-written via symlink",
		"+patched via symlink",
	}, "\n") + "\n"
	if err := PatchFile(acc, linkRel, tempDir, diff); err != nil {
		t.Fatalf("PatchFile through symlink failed: %v", err)
	}
	targetBytes, _ = os.ReadFile(targetPath)
	if string(targetBytes) != "patched via symlink\n" {
		t.Errorf("target file content = %q, want %q", string(targetBytes), "patched via symlink\n")
	}

	// 5. Existing deny-outside-root case
	outsideSecret := filepath.Join(outsideDir, "escape.txt")
	_ = os.WriteFile(outsideSecret, []byte("escape"), 0o600)
	outsideLink := filepath.Join(writableDir, "outside_link.txt")
	_ = os.Symlink(outsideSecret, outsideLink)

	if _, err := ReadFile(acc, "writable/outside_link.txt", tempDir, 0, 0, false); err == nil {
		t.Error("expected ReadFile through outside symlink to be denied")
	}
	if err := WriteFile(acc, "writable/outside_link.txt", tempDir, "hacked"); err == nil {
		t.Error("expected WriteFile through outside symlink to be denied")
	}
	buf.Reset()
	if err := CatFile(acc, "writable/outside_link.txt", tempDir, &buf); err == nil {
		t.Error("expected CatFile through outside symlink to be denied")
	}
	if err := PatchFile(acc, "writable/outside_link.txt", tempDir, diff); err == nil {
		t.Error("expected PatchFile through outside symlink to be denied")
	}
}

// (f) chain cap of 8 errors, cycle case errors
func TestSymlink_ChainsAndCycles(t *testing.T) {
	tempDir, acc, writableDir, _, _ := helperSetupMultiRootAccess(t)

	// 1. Direct cycle: c1 -> c2, c2 -> c1
	c1 := filepath.Join(writableDir, "c1")
	c2 := filepath.Join(writableDir, "c2")
	_ = os.Symlink("c2", c1)
	_ = os.Symlink("c1", c2)

	_, err := ReadFile(acc, "writable/c1", tempDir, 0, 0, false)
	if err == nil || !strings.Contains(err.Error(), "exceeded maximum of 8 hops") {
		t.Errorf("expected cycle to error with hop cap, got %v", err)
	}

	// 2. Self cycle: self -> self
	self := filepath.Join(writableDir, "self")
	_ = os.Symlink("self", self)
	_, err = ReadFile(acc, "writable/self", tempDir, 0, 0, false)
	if err == nil || !strings.Contains(err.Error(), "exceeded maximum of 8 hops") {
		t.Errorf("expected self cycle to error with hop cap, got %v", err)
	}

	// 3. Exactly 8 hops succeeds
	target8 := filepath.Join(writableDir, "target8.txt")
	_ = os.WriteFile(target8, []byte("eight hops\n"), 0o600)
	_ = os.Symlink("target8.txt", filepath.Join(writableDir, "h8"))
	for i := 7; i >= 1; i-- {
		_ = os.Symlink(fmt.Sprintf("h%d", i+1), filepath.Join(writableDir, fmt.Sprintf("h%d", i)))
	}
	content, err := ReadFile(acc, "writable/h1", tempDir, 0, 0, false)
	if err != nil {
		t.Fatalf("expected 8-hop chain to succeed, got: %v", err)
	}
	if content != "eight hops\n" {
		t.Errorf("got %q, want 'eight hops\n'", content)
	}

	// 4. Exceeding 8 hops (9 hops) errors
	_ = os.Symlink("h1", filepath.Join(writableDir, "h0"))
	_, err = ReadFile(acc, "writable/h0", tempDir, 0, 0, false)
	if err == nil || !strings.Contains(err.Error(), "exceeded maximum of 8 hops") {
		t.Errorf("expected 9-hop chain to error, got: %v", err)
	}
}

// (g) delete on a symlink removes only the link
func TestDeleteFile_SymlinkOnly(t *testing.T) {
	tempDir, acc, writableDir, _, _ := helperSetupMultiRootAccess(t)

	targetPath := filepath.Join(writableDir, "keep_target.txt")
	content := "important data that must not be deleted\n"
	if err := os.WriteFile(targetPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}

	linkPath := filepath.Join(writableDir, "delete_link.txt")
	if err := os.Symlink("keep_target.txt", linkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	if err := DeleteFile(acc, "writable/delete_link.txt", tempDir); err != nil {
		t.Fatalf("DeleteFile failed: %v", err)
	}

	// Symlink must be removed
	if _, err := os.Lstat(linkPath); !os.IsNotExist(err) {
		t.Errorf("expected symlink to be deleted, but it still exists")
	}

	// Target must be untouched
	targetData, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("target file was deleted or unreadable: %v", err)
	}
	if string(targetData) != content {
		t.Errorf("target file content modified: %q", string(targetData))
	}

	// Delete on dangling symlink removes the dangling link
	danglingLink := filepath.Join(writableDir, "del_dangling.txt")
	_ = os.Symlink("missing.txt", danglingLink)
	if err := DeleteFile(acc, "writable/del_dangling.txt", tempDir); err != nil {
		t.Fatalf("DeleteFile on dangling symlink failed: %v", err)
	}
	if _, err := os.Lstat(danglingLink); !os.IsNotExist(err) {
		t.Errorf("expected dangling symlink to be deleted")
	}
}

// (h) write/patch through dangling link errors
func TestSymlink_DanglingWritePatchError(t *testing.T) {
	tempDir, acc, writableDir, _, _ := helperSetupMultiRootAccess(t)

	danglingRel := "writable/dangling_action.txt"
	danglingPath := filepath.Join(writableDir, "dangling_action.txt")
	nonexistentPath := filepath.Join(writableDir, "missing_dest.txt")

	_ = os.Symlink("missing_dest.txt", danglingPath)

	// Write through dangling link must error
	err := WriteFile(acc, danglingRel, tempDir, "payload")
	if err == nil {
		t.Fatal("expected WriteFile through dangling symlink to error, got nil")
	}
	if _, err := os.Stat(nonexistentPath); !os.IsNotExist(err) {
		t.Error("WriteFile through dangling link must not auto-vivify the target")
	}
	fi, err := os.Lstat(danglingPath)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("dangling symlink must remain a symlink")
	}

	// Patch through dangling link must error
	diff := strings.Join([]string{
		"--- missing_dest.txt",
		"+++ missing_dest.txt",
		"@@ -1,1 +1,1 @@",
		"-old",
		"+new",
	}, "\n") + "\n"
	err = PatchFile(acc, danglingRel, tempDir, diff)
	if err == nil {
		t.Fatal("expected PatchFile through dangling symlink to error, got nil")
	}
	if _, err := os.Stat(nonexistentPath); !os.IsNotExist(err) {
		t.Error("PatchFile through dangling link must not auto-vivify the target")
	}
}

// (i) --force overwrites an existing link
func TestSymlink_ForceOverwrite(t *testing.T) {
	tempDir, acc, writableDir, _, _ := helperSetupMultiRootAccess(t)

	linkRel := "writable/switchable_link.txt"
	linkPath := filepath.Join(writableDir, "switchable_link.txt")

	// 1. Create initial link
	if err := SymlinkFile(acc, linkRel, "first.txt", tempDir, false); err != nil {
		t.Fatalf("first SymlinkFile failed: %v", err)
	}

	// 2. Without force, overwrite must error
	err := SymlinkFile(acc, linkRel, "second.txt", tempDir, false)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected already exists error without force, got %v", err)
	}
	target, _ := os.Readlink(linkPath)
	if target != "first.txt" {
		t.Errorf("target should still be first.txt, got %q", target)
	}

	// 3. With force, overwrite succeeds
	err = SymlinkFile(acc, linkRel, "second.txt", tempDir, true)
	if err != nil {
		t.Fatalf("SymlinkFile with force failed: %v", err)
	}
	target, _ = os.Readlink(linkPath)
	if target != "second.txt" {
		t.Errorf("target should now be second.txt, got %q", target)
	}
}

// (j) non-JSON output shows the `-> target` suffix
func TestListDir_NonJSONSymlinkSuffix(t *testing.T) {
	tempDir, acc, writableDir, _, _ := helperSetupMultiRootAccess(t)

	regularFile := filepath.Join(writableDir, "normal.txt")
	_ = os.WriteFile(regularFile, []byte("data"), 0o600)

	linkPath := filepath.Join(writableDir, "my_link.txt")
	_ = os.Symlink("normal.txt", linkPath)

	// Short non-JSON
	outShort, err := ListDir(acc, "writable", tempDir, false, false, false, false)
	if err != nil {
		t.Fatalf("ListDir short failed: %v", err)
	}
	if !strings.Contains(outShort, "my_link.txt -> normal.txt") {
		t.Errorf("expected short output to contain 'my_link.txt -> normal.txt', got %q", outShort)
	}
	if !strings.Contains(outShort, "normal.txt") {
		t.Errorf("expected short output to contain normal.txt, got %q", outShort)
	}

	// Long non-JSON
	outLong, err := ListDir(acc, "writable", tempDir, true, false, false, false)
	if err != nil {
		t.Fatalf("ListDir long failed: %v", err)
	}
	if !strings.Contains(outLong, "my_link.txt -> normal.txt") {
		t.Errorf("expected long output to contain 'my_link.txt -> normal.txt', got %q", outLong)
	}
}

// Chain test: entry A -> linkB (linkB inside read-covered root), linkB's target Z is
// BOTH nonexistent AND outside every granted root.
// Assert: (a) list classifies A as blocked (NOT dangling); (b) symlink creation through A is DENIED.
func TestSymlink_ChainToUncoveredTarget(t *testing.T) {
	tempDir, acc, writableDir, readonlyDir, outsideDir := helperSetupMultiRootAccess(t)

	// Target Z is nonexistent and outside every granted root
	targetZ := filepath.Join(outsideDir, "nonexistent_z.txt")
	if _, err := os.Stat(targetZ); !os.IsNotExist(err) {
		t.Fatalf("target Z must not exist: %v", err)
	}

	// Link B lives inside read-covered root (readonlyDir), pointing to outside nonexistent Z
	linkB := filepath.Join(readonlyDir, "linkB")
	if err := os.Symlink(targetZ, linkB); err != nil {
		t.Fatalf("failed to create linkB: %v", err)
	}

	// Entry A lives in writableDir, pointing to linkB
	entryA := filepath.Join(writableDir, "entryA")
	if err := os.Symlink("../readonly/linkB", entryA); err != nil {
		t.Fatalf("failed to create entryA: %v", err)
	}

	// (a) ListDir must classify entry A as "blocked", NOT "dangling"
	out, err := ListDir(acc, "writable", tempDir, false, false, false, true)
	if err != nil {
		t.Fatalf("ListDir failed: %v", err)
	}

	var entries []ListEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	var foundA *ListEntry
	for i := range entries {
		if entries[i].Name == "entryA" {
			foundA = &entries[i]
			break
		}
	}
	if foundA == nil {
		t.Fatalf("entryA not found in ListDir output: %s", out)
	}
	if foundA.Type != "symlink" {
		t.Errorf("entryA type = %q, want 'symlink'", foundA.Type)
	}
	if foundA.Resolved != "blocked" {
		t.Errorf("entryA resolved = %q, want 'blocked' (must NOT be 'dangling')", foundA.Resolved)
	}
	if strings.Contains(foundA.Resolved, "outside") || strings.Contains(foundA.Resolved, "nonexistent_z") {
		t.Errorf("entryA resolved leaked outside path: %q", foundA.Resolved)
	}

	// (b) Creating newlink -> entryA through the chain must be DENIED
	err = SymlinkFile(acc, "writable/newlink", "entryA", tempDir, false)
	if err == nil {
		t.Fatal("expected creation of newlink -> entryA to be DENIED, got nil")
	}
	if !strings.Contains(err.Error(), "read access denied") {
		t.Errorf("expected 'read access denied' error, got: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(writableDir, "newlink")); !os.IsNotExist(err) {
		t.Errorf("newlink must not have been created on failure")
	}

	// Also directly targeting linkB (which points to Z) must be DENIED
	err = SymlinkFile(acc, "writable/newlink_direct", "../readonly/linkB", tempDir, false)
	if err == nil {
		t.Fatal("expected creation of newlink_direct -> linkB to be DENIED, got nil")
	}
	if !strings.Contains(err.Error(), "read access denied") {
		t.Errorf("expected 'read access denied' error, got: %v", err)
	}
}

// Oracle-closure differential test: an EXISTING out-of-coverage target vs a NONEXISTENT
// out-of-coverage target must be treated identically by both list and creation
// (same blocked/denied outcome, indistinguishable responses proving no existence leak).
func TestSymlink_OracleClosureDifferential(t *testing.T) {
	tempDir, acc, writableDir, _, outsideDir := helperSetupMultiRootAccess(t)

	// 1. Existing out-of-coverage target
	existTarget := filepath.Join(outsideDir, "oracle_exist.txt")
	if err := os.WriteFile(existTarget, []byte("confidential data"), 0o600); err != nil {
		t.Fatalf("failed to write existTarget: %v", err)
	}

	// 2. Nonexistent out-of-coverage target
	missingTarget := filepath.Join(outsideDir, "oracle_missing.txt")
	_ = os.Remove(missingTarget)
	if _, err := os.Stat(missingTarget); !os.IsNotExist(err) {
		t.Fatalf("missingTarget must not exist")
	}

	// Create symlinks in writableDir to both targets
	linkExist := filepath.Join(writableDir, "link_to_exist")
	if err := os.Symlink(existTarget, linkExist); err != nil {
		t.Fatalf("failed to create link_to_exist: %v", err)
	}
	linkMissing := filepath.Join(writableDir, "link_to_missing")
	if err := os.Symlink(missingTarget, linkMissing); err != nil {
		t.Fatalf("failed to create link_to_missing: %v", err)
	}

	// --- Differential check on ListDir ---
	out, err := ListDir(acc, "writable", tempDir, false, false, false, true)
	if err != nil {
		t.Fatalf("ListDir failed: %v", err)
	}

	var entries []ListEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	byName := make(map[string]ListEntry)
	for _, e := range entries {
		byName[e.Name] = e
	}

	entryExist, okExist := byName["link_to_exist"]
	entryMissing, okMissing := byName["link_to_missing"]
	if !okExist || !okMissing {
		t.Fatalf("missing expected entries in ListDir output: %s", out)
	}

	// Both must be classified identically as "blocked"
	if entryExist.Resolved != "blocked" {
		t.Errorf("entryExist resolved = %q, want 'blocked'", entryExist.Resolved)
	}
	if entryMissing.Resolved != "blocked" {
		t.Errorf("entryMissing resolved = %q, want 'blocked'", entryMissing.Resolved)
	}
	if entryExist.Resolved != entryMissing.Resolved {
		t.Errorf("oracle leak: entryExist.Resolved (%q) != entryMissing.Resolved (%q)",
			entryExist.Resolved, entryMissing.Resolved)
	}

	// Neither may leak outside paths
	for _, e := range []ListEntry{entryExist, entryMissing} {
		if strings.Contains(e.Resolved, outsideDir) || strings.Contains(e.Resolved, "oracle") {
			t.Errorf("entry %s leaked outside path in resolved: %q", e.Name, e.Resolved)
		}
	}

	// --- Differential check on SymlinkFile creation ---
	errExist := SymlinkFile(acc, "writable/try_exist", existTarget, tempDir, false)
	errMissing := SymlinkFile(acc, "writable/try_missing", missingTarget, tempDir, false)

	if errExist == nil {
		t.Fatal("expected creation to existing outside target to be DENIED, got nil")
	}
	if errMissing == nil {
		t.Fatal("expected creation to missing outside target to be DENIED, got nil")
	}

	// Error messages must follow the exact same structure without leaking existence
	expectedPrefix := "read access denied for symlink target "
	if !strings.HasPrefix(errExist.Error(), expectedPrefix) {
		t.Errorf("errExist unexpected message: %v", errExist)
	}
	if !strings.HasPrefix(errMissing.Error(), expectedPrefix) {
		t.Errorf("errMissing unexpected message: %v", errMissing)
	}
	// Neither error may mention file existence, not-found, or stat errors
	for _, errMsg := range []string{errExist.Error(), errMissing.Error()} {
		if strings.Contains(strings.ToLower(errMsg), "not exist") ||
			strings.Contains(strings.ToLower(errMsg), "no such file") {
			t.Errorf("creation error leaked target existence: %q", errMsg)
		}
	}

	// Ensure neither link was created
	if _, err := os.Lstat(filepath.Join(writableDir, "try_exist")); !os.IsNotExist(err) {
		t.Error("try_exist link should not exist")
	}
	if _, err := os.Lstat(filepath.Join(writableDir, "try_missing")); !os.IsNotExist(err) {
		t.Error("try_missing link should not exist")
	}
}

// Tests for Mkdir (Decision D92)

func TestMkdir_Basic(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)

	dirRel := "new_directory"
	if err := Mkdir(acc, dirRel, tempDir, false); err != nil {
		t.Fatalf("Mkdir basic failed: %v", err)
	}

	fullPath := filepath.Join(tempDir, dirRel)
	fi, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat created directory failed: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("expected created path to be directory, got regular file")
	}
	perm := fi.Mode().Perm()
	if perm != 0o755 {
		t.Errorf("expected perm 0755, got %o", perm)
	}
}

func TestMkdir_WithoutParents_MissingParent(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)

	dirRel := filepath.Join("missing_parent", "new_directory")
	err := Mkdir(acc, dirRel, tempDir, false)
	if err == nil {
		t.Fatal("expected Mkdir without -p to fail when parent is missing, got nil")
	}
	if !strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("expected 'no such file or directory' error, got: %v", err)
	}

	fullPath := filepath.Join(tempDir, dirRel)
	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		t.Error("directory should not have been created")
	}
}

func TestMkdir_WithoutParents_TargetAlreadyExists(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)

	// 1. Target already exists as a directory
	dirRel := "existing_dir"
	fullPath := filepath.Join(tempDir, dirRel)
	if err := os.Mkdir(fullPath, 0o755); err != nil {
		t.Fatalf("failed to create existing dir: %v", err)
	}

	err := Mkdir(acc, dirRel, tempDir, false)
	if err == nil {
		t.Fatal("expected Mkdir without -p to fail when directory exists, got nil")
	}
	if !strings.Contains(err.Error(), "file exists") {
		t.Errorf("expected 'file exists' error, got: %v", err)
	}

	// 2. Target already exists as a regular file
	fileRel := "existing_file.txt"
	filePath := filepath.Join(tempDir, fileRel)
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatalf("failed to create existing file: %v", err)
	}

	err = Mkdir(acc, fileRel, tempDir, false)
	if err == nil {
		t.Fatal("expected Mkdir without -p to fail when regular file exists, got nil")
	}
	if !strings.Contains(err.Error(), "file exists") {
		t.Errorf("expected 'file exists' error, got: %v", err)
	}
}

func TestMkdir_WithParents_MultiLevel(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)

	dirRel := filepath.Join("level1", "level2", "level3")
	if err := Mkdir(acc, dirRel, tempDir, true); err != nil {
		t.Fatalf("Mkdir with parents failed: %v", err)
	}

	fullPath := filepath.Join(tempDir, dirRel)
	fi, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat multi-level directory failed: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("expected created path to be directory, got regular file")
	}
}

func TestMkdir_WithParents_Idempotence(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)

	// 1. Repeated creation of existing directory succeeds with nil error
	dirRel := filepath.Join("a", "b", "c")
	if err := Mkdir(acc, dirRel, tempDir, true); err != nil {
		t.Fatalf("initial Mkdir failed: %v", err)
	}
	if err := Mkdir(acc, dirRel, tempDir, true); err != nil {
		t.Fatalf("idempotent Mkdir failed on existing directory: %v", err)
	}

	// 2. Target exists as a regular file - must return error
	fileRel := "a_file.txt"
	filePath := filepath.Join(tempDir, fileRel)
	if err := os.WriteFile(filePath, []byte("data"), 0o644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	err := Mkdir(acc, fileRel, tempDir, true)
	if err == nil {
		t.Fatal("expected Mkdir with -p to fail when target is a regular file, got nil")
	}
	if !strings.Contains(err.Error(), "file exists") {
		t.Errorf("expected 'file exists' error, got: %v", err)
	}
}

func TestMkdir_AccessDenial_OutsideWriteRoot(t *testing.T) {
	tempDir, acc, _, _, _ := helperSetupMultiRootAccess(t)

	// Without parents
	err := Mkdir(acc, "../outside/new_dir", tempDir, false)
	if err == nil {
		t.Fatal("expected Mkdir outside write root to fail without -p, got nil")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected access denied error, got: %v", err)
	}

	// With parents
	err = Mkdir(acc, "../outside/sub/new_dir", tempDir, true)
	if err == nil {
		t.Fatal("expected Mkdir outside write root to fail with -p, got nil")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected access denied error, got: %v", err)
	}
}

func TestMkdir_AccessDenial_ReadOnlyRoot(t *testing.T) {
	tempDir, acc, _, readonlyDir, _ := helperSetupMultiRootAccess(t)

	// Without parents
	err := Mkdir(acc, "readonly/new_dir", tempDir, false)
	if err == nil {
		t.Fatal("expected Mkdir in readonly root to fail without -p, got nil")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected access denied error, got: %v", err)
	}

	// With parents
	err = Mkdir(acc, "readonly/sub/new_dir", tempDir, true)
	if err == nil {
		t.Fatal("expected Mkdir in readonly root to fail with -p, got nil")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected access denied error, got: %v", err)
	}

	// Verify nothing was created in readonlyDir
	if _, err := os.Stat(filepath.Join(readonlyDir, "new_dir")); !os.IsNotExist(err) {
		t.Error("new_dir should not have been created in readonlyDir")
	}
	if _, err := os.Stat(filepath.Join(readonlyDir, "sub")); !os.IsNotExist(err) {
		t.Error("sub should not have been created in readonlyDir")
	}
}

func TestMkdir_AccessDenial_SymlinkEscaping(t *testing.T) {
	tempDir, acc, writableDir, _, outsideDir := helperSetupMultiRootAccess(t)

	// Create symlink inside writable pointing to outside
	linkPath := filepath.Join(writableDir, "esc_link")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Without parents
	err := Mkdir(acc, "writable/esc_link/escaped_dir", tempDir, false)
	if err == nil {
		t.Fatal("expected Mkdir through escaping symlink to fail without -p, got nil")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected access denied error, got: %v", err)
	}

	// With parents
	err = Mkdir(acc, "writable/esc_link/sub/escaped_dir", tempDir, true)
	if err == nil {
		t.Fatal("expected Mkdir through escaping symlink to fail with -p, got nil")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected access denied error, got: %v", err)
	}

	// Verify nothing created in outsideDir
	if _, err := os.Stat(filepath.Join(outsideDir, "escaped_dir")); !os.IsNotExist(err) {
		t.Error("escaped_dir should not have been created in outsideDir")
	}
	if _, err := os.Stat(filepath.Join(outsideDir, "sub")); !os.IsNotExist(err) {
		t.Error("sub should not have been created in outsideDir")
	}
}

func TestMkdir_AccessDenial_IntermediateDirOutsideWriteRoot(t *testing.T) {
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to eval symlinks: %v", err)
	}

	// Access grants only a deep subdirectory
	accessContent := "w: deep/allowed_root\n"
	accessFile := filepath.Join(tempDir, AccessFileName)
	if err := os.WriteFile(accessFile, []byte(accessContent), 0o600); err != nil {
		t.Fatalf("failed to write access file: %v", err)
	}

	acc, err := LoadAccess(tempDir)
	if err != nil {
		t.Fatalf("LoadAccess failed: %v", err)
	}

	// Target is inside granted root, but ancestor "deep" does not exist yet on disk.
	// Longest existing ancestor is tempDir, which is NOT in writableRoots.
	err = Mkdir(acc, "deep/allowed_root/sub", tempDir, true)
	if err == nil {
		t.Fatal("expected Mkdir with -p to fail when intermediate ancestor is outside write root, got nil")
	}
	if !strings.Contains(err.Error(), "access denied") {
		t.Errorf("expected access denied error, got: %v", err)
	}

	// Verify "deep" was not created on disk
	if _, err := os.Stat(filepath.Join(tempDir, "deep")); !os.IsNotExist(err) {
		t.Error("ancestor directory 'deep' should not have been created")
	}
}

func TestMkdir_AccessDenial_AccessFileName(t *testing.T) {
	tempDir, acc := helperSetupAccess(t)

	// Attempt to mkdir targeting FILES_RW_ACCESS itself
	err := Mkdir(acc, AccessFileName, tempDir, false)
	if err == nil {
		t.Fatal("expected Mkdir on FILES_RW_ACCESS to be denied, got nil")
	}
	if !strings.Contains(err.Error(), "always denied") && !strings.Contains(err.Error(), "access denied") {
		t.Errorf("unexpected error: %v", err)
	}

	err = Mkdir(acc, AccessFileName, tempDir, true)
	if err == nil {
		t.Fatal("expected Mkdir -p on FILES_RW_ACCESS to be denied, got nil")
	}
	if !strings.Contains(err.Error(), "always denied") && !strings.Contains(err.Error(), "access denied") {
		t.Errorf("unexpected error: %v", err)
	}
}

