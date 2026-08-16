package filesrw

import (
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

	out, err := ListDir(acc, ".", tempDir, false, false, false)
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
