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
