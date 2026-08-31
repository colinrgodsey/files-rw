package main

import (
	"bytes"
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
