package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteCmd_EmptyStdinRejection(t *testing.T) {
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to eval symlinks: %v", err)
	}

	accessFile := filepath.Join(tempDir, "FILES_RW_ACCESS")
	if err := os.WriteFile(accessFile, []byte("w: .\n"), 0600); err != nil {
		t.Fatalf("failed to write access file: %v", err)
	}

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer os.Chdir(origWd)

	targetPath := filepath.Join(tempDir, "empty.txt")

	// 1. Without --allow-empty, empty stdin must be rejected
	writeAllowEmpty = false
	rootCmd.SetArgs([]string{"write", targetPath})
	rootCmd.SetIn(bytes.NewReader([]byte("")))
	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("expected write to fail on empty stdin without --allow-empty, got nil")
	}
	if !strings.Contains(err.Error(), "refusing to write empty content") || !strings.Contains(err.Error(), "--allow-empty") {
		t.Errorf("unexpected error message: %v", err)
	}

	// 2. With --allow-empty, empty stdin must succeed and create 0-byte file
	writeAllowEmpty = false // reset flag, let cobra parse it
	rootCmd.SetArgs([]string{"write", "--allow-empty", targetPath})
	rootCmd.SetIn(bytes.NewReader([]byte("")))
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("expected write with --allow-empty to succeed, got: %v", err)
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("target file was not created: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("expected 0 bytes, got %d", info.Size())
	}

	// 3. With non-empty stdin, write succeeds normally
	rootCmd.SetArgs([]string{"write", targetPath})
	rootCmd.SetIn(bytes.NewReader([]byte("hello world\n")))
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("expected write with content to succeed, got: %v", err)
	}
	content, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("failed reading file: %v", err)
	}
	if string(content) != "hello world\n" {
		t.Errorf("content mismatch: %q", string(content))
	}
}

func TestSkillCmd(t *testing.T) {
	// 1. files-rw skill (list bundled skills)
	var outBuf bytes.Buffer
	rootCmd.SetOut(&outBuf)
	rootCmd.SetArgs([]string{"skill"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("expected skill list to succeed, got: %v", err)
	}

	// 2. files-rw skill files-rw (print skill content)
	rootCmd.SetArgs([]string{"skill", "files-rw"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("expected skill files-rw to succeed, got: %v", err)
	}

	// 3. files-rw skill unknown (should return error)
	rootCmd.SetArgs([]string{"skill", "nonexistent"})
	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent skill, got nil")
	}
	if !strings.Contains(err.Error(), "unknown skill") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseSkillContent(t *testing.T) {
	sample := `---
name: test-skill
description: A test skill description
always_load: true
---

# Test Skill
Body content here.`

	info, err := parseSkillContent(sample, "default-name")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if info.Name != "test-skill" {
		t.Errorf("expected name 'test-skill', got %q", info.Name)
	}
	if info.Description != "A test skill description" {
		t.Errorf("expected description 'A test skill description', got %q", info.Description)
	}
	if !info.AlwaysLoad {
		t.Errorf("expected AlwaysLoad to be true")
	}

	// Fallback when frontmatter is missing
	noFM := "# Just markdown"
	info2, err := parseSkillContent(noFM, "fallback")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if info2.Name != "fallback" {
		t.Errorf("expected name 'fallback', got %q", info2.Name)
	}
	if info2.Description != "Skill fallback" {
		t.Errorf("expected description 'Skill fallback', got %q", info2.Description)
	}
}

func captureStdout(f func() error) (string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	oldStdout := os.Stdout
	os.Stdout = w

	outChan := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		_ = r.Close()
		outChan <- buf.String()
	}()

	runErr := f()
	_ = w.Close()
	os.Stdout = oldStdout
	out := <-outChan
	return out, runErr
}

func TestSymlinkCmd(t *testing.T) {
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to eval symlinks: %v", err)
	}

	accessFile := filepath.Join(tempDir, "FILES_RW_ACCESS")
	if err := os.WriteFile(accessFile, []byte("w: .\n"), 0o600); err != nil {
		t.Fatalf("failed to write access file: %v", err)
	}

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer os.Chdir(origWd)

	targetFile := filepath.Join(tempDir, "target.txt")
	if err := os.WriteFile(targetFile, []byte("target content"), 0o600); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}

	// 1. Create symlink
	symlinkForce = false
	rootCmd.SetArgs([]string{"symlink", "link.txt", "target.txt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("symlink cmd failed: %v", err)
	}
	linkPath := filepath.Join(tempDir, "link.txt")
	gotTarget, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("failed to readlink: %v", err)
	}
	if gotTarget != "target.txt" {
		t.Errorf("readlink = %q, want 'target.txt'", gotTarget)
	}

	// 2. Overwrite without force must fail
	rootCmd.SetArgs([]string{"symlink", "link.txt", "other.txt"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error without --force, got nil")
	}

	// 3. Overwrite with --force succeeds
	symlinkForce = false
	rootCmd.SetArgs([]string{"symlink", "--force", "link.txt", "other.txt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("symlink cmd with --force failed: %v", err)
	}
	gotTarget, err = os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("failed to readlink: %v", err)
	}
	if gotTarget != "other.txt" {
		t.Errorf("readlink = %q, want 'other.txt'", gotTarget)
	}
}

func TestListCmd_JSONAndSuffix(t *testing.T) {
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to eval symlinks: %v", err)
	}

	accessFile := filepath.Join(tempDir, "FILES_RW_ACCESS")
	if err := os.WriteFile(accessFile, []byte("w: .\n"), 0o600); err != nil {
		t.Fatalf("failed to write access file: %v", err)
	}

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer os.Chdir(origWd)

	targetFile := filepath.Join(tempDir, "target.txt")
	if err := os.WriteFile(targetFile, []byte("hello"), 0o600); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}
	linkPath := filepath.Join(tempDir, "my_link.txt")
	if err := os.Symlink("target.txt", linkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// 1. Non-JSON list shows -> target suffix
	listLong = false
	listAll = false
	listRecursive = false
	listJSON = false
	out, err := captureStdout(func() error {
		rootCmd.SetArgs([]string{"list", "."})
		return rootCmd.Execute()
	})
	if err != nil {
		t.Fatalf("list cmd failed: %v", err)
	}
	if !strings.Contains(out, "my_link.txt -> target.txt") {
		t.Errorf("expected output to contain 'my_link.txt -> target.txt', got: %q", out)
	}

	// 2. JSON list outputs structured entries
	listLong = false
	listAll = false
	listRecursive = false
	listJSON = false
	jsonOut, err := captureStdout(func() error {
		rootCmd.SetArgs([]string{"list", "--json", "."})
		return rootCmd.Execute()
	})
	if err != nil {
		t.Fatalf("list --json cmd failed: %v", err)
	}

	type jsonEntry struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Target   string `json:"target"`
		Resolved string `json:"resolved"`
	}
	var entries []jsonEntry
	if err := json.Unmarshal([]byte(jsonOut), &entries); err != nil {
		t.Fatalf("failed to unmarshal JSON output %q: %v", jsonOut, err)
	}

	var foundLink *jsonEntry
	for i := range entries {
		if entries[i].Name == "my_link.txt" {
			foundLink = &entries[i]
			break
		}
	}
	if foundLink == nil {
		t.Fatalf("link entry 'my_link.txt' not found in JSON entries: %+v", entries)
	}
	if foundLink.Type != "symlink" {
		t.Errorf("type = %q, want 'symlink'", foundLink.Type)
	}
	if foundLink.Target != "target.txt" {
		t.Errorf("target = %q, want 'target.txt'", foundLink.Target)
	}
	if foundLink.Resolved != targetFile {
		t.Errorf("resolved = %q, want %q", foundLink.Resolved, targetFile)
	}
}

func TestMkdirCmd(t *testing.T) {
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("failed to eval symlinks: %v", err)
	}

	accessFile := filepath.Join(tempDir, "FILES_RW_ACCESS")
	if err := os.WriteFile(accessFile, []byte("w: .\n"), 0o600); err != nil {
		t.Fatalf("failed to write access file: %v", err)
	}

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get wd: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer os.Chdir(origWd)

	// 1. Argument validation: exact 1 argument required
	rootCmd.SetArgs([]string{"mkdir"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error with 0 args, got nil")
	}

	rootCmd.SetArgs([]string{"mkdir", "a", "b"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error with 2 args, got nil")
	}

	// 2. Basic mkdir without -p
	mkdirParents = false
	rootCmd.SetArgs([]string{"mkdir", "single_dir"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected mkdir single_dir to succeed, got: %v", err)
	}
	fi, err := os.Stat(filepath.Join(tempDir, "single_dir"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("expected single_dir to exist as a directory, got err: %v", err)
	}

	// 3. Target already exists without -p -> fails with "file exists"
	mkdirParents = false
	rootCmd.SetArgs([]string{"mkdir", "single_dir"})
	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("expected mkdir single_dir to fail when exists, got nil")
	}
	if !strings.Contains(err.Error(), "file exists") {
		t.Errorf("expected 'file exists' error, got: %v", err)
	}

	// 4. Missing parent without -p -> fails with "no such file or directory"
	mkdirParents = false
	rootCmd.SetArgs([]string{"mkdir", "missing_parent/sub_dir"})
	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("expected mkdir missing_parent/sub_dir to fail without -p, got nil")
	}
	if !strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("expected 'no such file or directory' error, got: %v", err)
	}

	// 5. With -p flag: creates intermediate parents
	mkdirParents = false
	rootCmd.SetArgs([]string{"mkdir", "-p", "nest1/nest2/nest3"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected mkdir -p to succeed, got: %v", err)
	}
	fi, err = os.Stat(filepath.Join(tempDir, "nest1", "nest2", "nest3"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("expected nest1/nest2/nest3 to exist as directory, got err: %v", err)
	}

	// 6. With --parents flag: idempotent on existing directory
	mkdirParents = false
	rootCmd.SetArgs([]string{"mkdir", "--parents", "nest1/nest2/nest3"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("expected mkdir --parents to succeed idempotently, got: %v", err)
	}
}
