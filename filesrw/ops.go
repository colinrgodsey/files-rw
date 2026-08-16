package filesrw

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bluekeyes/go-gitdiff/gitdiff"
)

// isBinary is a cheap heuristic (matches most agent-harness Read tools):
// a NUL byte anywhere in the sampled content means "not text".
func isBinary(data []byte) bool {
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	return bytes.IndexByte(sample, 0) != -1
}

// MaxReadSizeBytes is the maximum allowed byte size for a single read operation (200KB).
const MaxReadSizeBytes = 200 * 1024

// ReadFile opens path via acc.OpenFile and returns its content, optionally restricted to the inclusive
// 1-indexed [start, end] line range. If numbered is true, output is cat -n
// formatted ("%6d\t%s\n"). If false, raw text is returned. If output exceeds
// MaxReadSizeBytes, an error is returned suggesting line-based pagination.
func ReadFile(acc *Access, path, cwd string, start, end int, numbered bool) (string, error) {
	f, canonPath, err := acc.OpenFile(path, cwd, false, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", canonPath, err)
	}
	if isBinary(data) {
		return "", fmt.Errorf("%s looks like a binary file - refusing to read it as text", canonPath)
	}

	if start == 0 && end == 0 && !numbered {
		if len(data) > MaxReadSizeBytes {
			return "", fmt.Errorf("%s size is %d bytes, which exceeds the %d byte read limit - use --start and --end for line pagination", canonPath, len(data), MaxReadSizeBytes)
		}
		return string(data), nil
	}

	lines := strings.Split(string(data), "\n")
	// A trailing newline produces one spurious empty final element; drop it
	// so line numbers match what's actually in the file.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	from := 1
	to := len(lines)
	if start > 0 {
		from = start
	}
	if end > 0 {
		to = end
	}
	if from < 1 {
		from = 1
	}
	if to > len(lines) {
		to = len(lines)
	}
	if from > to {
		return "", nil
	}

	if !numbered {
		selected := lines[from-1 : to]
		totalBytes := 0
		for _, l := range selected {
			totalBytes += len(l) + 1
		}
		if totalBytes > MaxReadSizeBytes {
			return "", fmt.Errorf("%s selected range lines %d..%d is %d bytes, which exceeds the %d byte read limit - use --start and --end for line pagination", canonPath, from, to, totalBytes, MaxReadSizeBytes)
		}
		return strings.Join(selected, "\n") + "\n", nil
	}

	var b strings.Builder
	for i := from; i <= to; i++ {
		fmt.Fprintf(&b, "%6d\t%s\n", i, lines[i-1])
	}
	out := b.String()
	if len(out) > MaxReadSizeBytes {
		return "", fmt.Errorf("%s formatted output is %d bytes, which exceeds the %d byte read limit - use --start and --end for line pagination", canonPath, len(out), MaxReadSizeBytes)
	}
	return out, nil
}

// WriteFile atomically overwrites (or creates) path with content,
// creating any missing parent directories first. Atomic via write-to-temp +
// rename, so a crash mid-write never leaves a corrupted/partial file behind.
func WriteFile(acc *Access, path, cwd string, content string) error {
	canonPath, err := acc.Resolve(path, cwd, true)
	if err != nil {
		return err
	}

	dir := filepath.Dir(canonPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create parent directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".files-rw-write-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once renamed

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write %s: %w", canonPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to write %s: %w", canonPath, err)
	}

	if err := os.Rename(tmpPath, canonPath); err != nil {
		return fmt.Errorf("failed to finalize write to %s: %w", canonPath, err)
	}

	// Verify hardlink safety on finalized file
	if info, err := os.Stat(canonPath); err == nil {
		if err := acc.checkHardlinkSafety(info, true); err != nil {
			_ = os.Remove(canonPath)
			return fmt.Errorf("failed to finalize write to %s: %w", canonPath, err)
		}
	}
	return nil
}

// CopyFile reads raw bytes from srcPath using open file handles and writes them to dstPath.
func CopyFile(acc *Access, srcPath, dstPath, cwd string) error {
	srcFile, canonSrc, err := acc.OpenFile(srcPath, cwd, false, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	data, err := io.ReadAll(srcFile)
	if err != nil {
		return fmt.Errorf("failed to read source file %s: %w", canonSrc, err)
	}

	return WriteFile(acc, dstPath, cwd, string(data))
}

// MoveFile moves srcPath to dstPath using os.Rename, falling back to copy + delete
// if cross-device move is required.
func MoveFile(acc *Access, srcPath, dstPath, cwd string) error {
	canonSrc, err := acc.Resolve(srcPath, cwd, true)
	if err != nil {
		return err
	}
	canonDst, err := acc.Resolve(dstPath, cwd, true)
	if err != nil {
		return err
	}

	dir := filepath.Dir(canonDst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create parent directory %s: %w", dir, err)
	}

	err = os.Rename(canonSrc, canonDst)
	if err == nil {
		return nil
	}

	// Fallback for cross-device renames or filesystem boundaries
	if err := CopyFile(acc, srcPath, dstPath, cwd); err != nil {
		return fmt.Errorf("failed to move %s to %s: %w", canonSrc, canonDst, err)
	}
	if err := DeleteFile(acc, srcPath, cwd); err != nil {
		return fmt.Errorf("copied %s to %s but failed to remove original source: %w", canonSrc, canonDst, err)
	}
	return nil
}

// DeleteFile removes path after verifying access.
func DeleteFile(acc *Access, path, cwd string) error {
	canonPath, err := acc.Resolve(path, cwd, true)
	if err != nil {
		return err
	}
	if err := os.Remove(canonPath); err != nil {
		return fmt.Errorf("failed to delete %s: %w", canonPath, err)
	}
	return nil
}

// EditFile replaces oldStr with newStr in path after reading through an open handle.
func EditFile(acc *Access, path, cwd string, oldStr, newStr string, replaceAll bool) error {
	if oldStr == "" {
		return fmt.Errorf("old string must not be empty")
	}

	f, canonPath, err := acc.OpenFile(path, cwd, true, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", canonPath, err)
	}

	if isBinary(data) {
		return fmt.Errorf("%s looks like a binary file - refusing to edit it as text", canonPath)
	}
	content := string(data)

	count := strings.Count(content, oldStr)
	if count == 0 {
		return fmt.Errorf("old string not found in %s", canonPath)
	}
	if count > 1 && !replaceAll {
		return fmt.Errorf("old string appears %d times in %s - supply more surrounding context to make it unique, or pass --replace-all", count, canonPath)
	}

	var updated string
	if replaceAll {
		updated = strings.ReplaceAll(content, oldStr, newStr)
	} else {
		updated = strings.Replace(content, oldStr, newStr, 1)
	}

	return WriteFile(acc, path, cwd, updated)
}

// PatchFile applies a unified diff to path in memory using gitdiff.Parse and gitdiff.Apply,
// reading through an open handle and writing atomically via WriteFile.
func PatchFile(acc *Access, path, cwd string, diff string) error {
	files, _, err := gitdiff.Parse(strings.NewReader(diff))
	if err != nil {
		return fmt.Errorf("patch rejected: invalid unified diff: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("patch rejected: diff contains no valid hunks or files")
	}

	f, canonPath, err := acc.OpenFile(path, cwd, true, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", canonPath, err)
	}

	var buf bytes.Buffer
	if err := gitdiff.Apply(&buf, bytes.NewReader(data), files[0]); err != nil {
		return fmt.Errorf("patch failed: %w", err)
	}

	return WriteFile(acc, path, cwd, buf.String())
}

// ListDir shells out to the system `ls` for path, passing through only
// a fixed set of recognized boolean flags.
func ListDir(acc *Access, path, cwd string, long, all, recursive bool) (string, error) {
	canonPath, err := acc.Resolve(path, cwd, false)
	if err != nil {
		return "", err
	}

	if _, err := exec.LookPath("ls"); err != nil {
		return "", fmt.Errorf("the \"ls\" command is not available on PATH: %w", err)
	}

	var flags []string
	if long {
		flags = append(flags, "-l")
	}
	if all {
		flags = append(flags, "-a")
	}
	if recursive {
		flags = append(flags, "-R")
	}
	args := append(flags, "--", canonPath)

	cmd := exec.Command("ls", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ls failed: %w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// TailFile opens path via acc.OpenFile and returns the last numLines lines (default 10)
// along with a total line count header ("Total lines: N\n"). If numbered is true, output is
// cat -n formatted ("%6d\t%s\n").
func TailFile(acc *Access, path, cwd string, numLines int, numbered bool) (string, error) {
	if numLines <= 0 {
		numLines = 10
	}

	f, canonPath, err := acc.OpenFile(path, cwd, false, os.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", canonPath, err)
	}
	if isBinary(data) {
		return "", fmt.Errorf("%s looks like a binary file - refusing to read it as text", canonPath)
	}

	rawLines := strings.Split(string(data), "\n")
	if len(rawLines) > 0 && rawLines[len(rawLines)-1] == "" {
		rawLines = rawLines[:len(rawLines)-1]
	}
	totalLines := len(rawLines)

	from := totalLines - numLines + 1
	if from < 1 {
		from = 1
	}
	to := totalLines

	var b strings.Builder
	fmt.Fprintf(&b, "Total lines: %d\n", totalLines)

	if from <= to && totalLines > 0 {
		if !numbered {
			for i := from; i <= to; i++ {
				b.WriteString(rawLines[i-1])
				b.WriteByte('\n')
			}
		} else {
			for i := from; i <= to; i++ {
				fmt.Fprintf(&b, "%6d\t%s\n", i, rawLines[i-1])
			}
		}
	}

	out := b.String()
	if len(out) > MaxReadSizeBytes {
		return "", fmt.Errorf("%s tail output is %d bytes, which exceeds the %d byte read limit - use a smaller line count", canonPath, len(out), MaxReadSizeBytes)
	}
	return out, nil
}

// AppendFile opens path via acc.OpenFile with write access and appends content directly to the file.
func AppendFile(acc *Access, path, cwd string, content string) error {
	canonPath, err := acc.Resolve(path, cwd, true)
	if err != nil {
		return err
	}
	dir := filepath.Dir(canonPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create parent directory %s: %w", dir, err)
	}

	f, canon, err := acc.OpenFile(path, cwd, true, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return fmt.Errorf("failed to append to %s: %w", canon, err)
	}
	return nil
}
