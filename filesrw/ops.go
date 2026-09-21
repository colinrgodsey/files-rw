package filesrw

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

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

// MaxCatSizeBytes is the maximum allowed byte size for a single cat operation (30MB).
const MaxCatSizeBytes = 30 * 1024 * 1024

// CatFile opens path via acc.OpenFile and streams its raw bytes directly to w.
// Bypasses the text/isBinary check entirely. Enforces a 30MB size limit via
// os.Stat check before streaming.
func CatFile(acc *Access, path, cwd string, w io.Writer) error {
	f, canonPath, err := acc.OpenFile(path, cwd, false, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", canonPath, err)
	}

	if st.Size() > MaxCatSizeBytes {
		return fmt.Errorf("%s size is %d bytes, which exceeds the %d byte cat limit", canonPath, st.Size(), MaxCatSizeBytes)
	}

	if _, err := io.Copy(w, f); err != nil {
		return fmt.Errorf("failed to stream %s: %w", canonPath, err)
	}
	return nil
}

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
	return writeFileReader(acc, path, cwd, strings.NewReader(content), 0)
}

// writeFileReader implements WriteFile for an arbitrary reader, optionally applying a
// destination mode. A zero mode leaves CreateTemp's 0600 default unchanged. Shared by
// WriteFile (string API) and CopyFile (streaming API) so both get the same temp+rename
// atomicity and the same pre-rename hardlink guard.
func writeFileReader(acc *Access, path, cwd string, r io.Reader, mode os.FileMode) error {
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

	if _, err := io.Copy(tmp, r); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write %s: %w", canonPath, err)
	}
	if mode != 0 {
		if err := tmp.Chmod(mode); err != nil {
			tmp.Close()
			return fmt.Errorf("failed to set mode %o on %s: %w", mode, canonPath, err)
		}
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to write %s: %w", canonPath, err)
	}

	// Hardlink guard BEFORE publishing: what matters is whether the destination was a
	// multi-linked file at the moment the write replaces it. After the rename the freshly
	// installed temp file has nlink 1 by construction, so checking post-rename could never
	// see the guarded pre-state.
	if err := guardDestinationBeforeWrite(acc, canonPath); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, canonPath); err != nil {
		return fmt.Errorf("failed to finalize write to %s: %w", canonPath, err)
	}
	return nil
}

// guardDestinationBeforeWrite refuses to overwrite a destination that is a multi-linked
// file at the moment just before the temp-file rename publishes the new content, and
// fails closed when the destination cannot be statted. It is split out from
// writeFileReader so the TOCTOU window it guards (destination changed to a multi-link
// AFTER Resolve validated it) is directly testable: Resolve's own hardlink check can only
// see the destination as it was when Resolve ran.
func guardDestinationBeforeWrite(acc *Access, canonPath string) error {
	info, err := os.Lstat(canonPath)
	if err == nil {
		if err := acc.checkHardlinkSafety(info, true); err != nil {
			return fmt.Errorf("refusing to overwrite multi-linked file %s: %w", canonPath, err)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	// An EACCES on a parent or a dangling-symlink Lstat failure is a fail-closed error:
	// skipping the check would silently keep the delete-by-path hazard the guard exists to
	// prevent, so the write refuses rather than proceeding unpoliced.
	return fmt.Errorf("failed to stat destination before write %s: %w", canonPath, err)
}

// CopyFile copies srcPath to dstPath streaming (no whole-file buffer) and preserves the
// source file mode on the destination, matching the inode-preserving rename path.
func CopyFile(acc *Access, srcPath, dstPath, cwd string) error {
	srcFile, canonSrc, err := acc.OpenFile(srcPath, cwd, false, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file %s: %w", canonSrc, err)
	}
	mode := srcInfo.Mode().Perm()

	if err := writeFileReader(acc, dstPath, cwd, srcFile, mode); err != nil {
		return err
	}
	return nil
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

	// Stat before the rename so the cross-device fallback can preserve mode and mtime,
	// keeping both move paths (inode-preserving rename vs copy+delete) observably identical.
	srcInfo, statErr := os.Lstat(canonSrc)

	err = os.Rename(canonSrc, canonDst)
	if err == nil {
		return nil
	}

	// Fallback for cross-device renames or filesystem boundaries
	if err := CopyFile(acc, srcPath, dstPath, cwd); err != nil {
		return fmt.Errorf("failed to move %s to %s: %w", canonSrc, canonDst, err)
	}
	// Mode was applied by CopyFile; mtime needs explicit restore here because the fallback
	// writes fresh content. A moved file whose mtime silently jumps to "now" is the same
	// class of surprise as the 0600-mode bug this fixes.
	if statErr == nil {
		if canonDstInfo, err := os.Lstat(canonDst); err == nil {
			_ = os.Chtimes(canonDst, canonDstInfo.ModTime(), srcInfo.ModTime())
			// Chtimes best-effort: mtime restoration is the documented difference between
			// cross-device and same-device moves, but a failure here must not roll back a
			// completed move - the data and mode are already in place.
		}
	}
	if err := DeleteFile(acc, srcPath, cwd); err != nil {
		return fmt.Errorf("copied %s to %s but failed to remove original source: %w", canonSrc, canonDst, err)
	}
	return nil
}

// DeleteFile removes path after verifying access.
// If path is a symlink, only the symlink itself is removed, never the target.
func DeleteFile(acc *Access, path, cwd string) error {
	canonPath, err := acc.ResolveNoFollow(path, cwd, true)
	if err != nil {
		return err
	}
	if err := os.Remove(canonPath); err != nil {
		return fmt.Errorf("failed to delete %s: %w", canonPath, err)
	}
	return nil
}

// SymlinkFile creates a symlink at linkPath pointing to target.
// Target is stored verbatim (relative stays relative).
// If force is true, overwrites an existing link or file.
func SymlinkFile(acc *Access, linkPath, target, cwd string, force bool) error {
	canonLink, err := acc.ResolveSymlinkCreation(linkPath, target, cwd)
	if err != nil {
		return err
	}

	dir := filepath.Dir(canonLink)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create parent directory %s: %w", dir, err)
	}

	fi, err := os.Lstat(canonLink)
	if err == nil {
		if !force {
			return fmt.Errorf("file %s already exists - use --force to overwrite", linkPath)
		}
		if fi.IsDir() {
			return fmt.Errorf("cannot overwrite directory %s with symlink", linkPath)
		}
		if err := os.Remove(canonLink); err != nil {
			return fmt.Errorf("failed to remove existing file %s: %w", canonLink, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat %s: %w", canonLink, err)
	}

	if err := os.Symlink(target, canonLink); err != nil {
		return fmt.Errorf("failed to create symlink %s: %w", linkPath, err)
	}
	return nil
}

// Mkdir creates a directory at path after verifying write access in acc.
// If parents is false:
//   - returns an error if the directory already exists ("file exists")
//   - returns an error if the parent directory does not exist ("no such file or directory")
//   - creates the directory with mode 0755
//
// If parents is true:
//   - verifies that all created intermediate directories and the longest existing ancestor
//     reside within a write-granted root in acc
//   - creates target and missing parent directories with mode 0755 idempotently
//   - returns nil if the target already exists and is a directory
//   - returns an error if the target exists but is a regular file
func Mkdir(acc *Access, path, cwd string, parents bool) error {
	canonPath, err := acc.Resolve(path, cwd, true)
	if err != nil {
		return err
	}

	if !parents {
		if _, err := os.Stat(canonPath); err == nil {
			return fmt.Errorf("mkdir %s: file exists", path)
		}
		if _, err := os.Stat(filepath.Dir(canonPath)); err != nil {
			return fmt.Errorf("mkdir %s: no such file or directory", path)
		}
		if err := os.Mkdir(canonPath, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", path, err)
		}
		return nil
	}

	fi, err := os.Stat(canonPath)
	if err == nil {
		if fi.IsDir() {
			return nil
		}
		return fmt.Errorf("mkdir %s: file exists", path)
	}

	curr := filepath.Dir(canonPath)
	var intermediateDirs []string
	for {
		st, err := os.Stat(curr)
		if err == nil {
			if !st.IsDir() {
				return fmt.Errorf("mkdir %s: not a directory: %s", path, curr)
			}
			break
		}
		intermediateDirs = append(intermediateDirs, curr)
		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}

	if !acc.IsWritable(curr) {
		return fmt.Errorf("write access denied for %q - ancestor directory %q is not within a write-granted root", path, curr)
	}

	for _, d := range intermediateDirs {
		if !acc.IsWritable(d) {
			return fmt.Errorf("write access denied for %q - intermediate directory %q is not within a write-granted root", path, d)
		}
	}

	if err := os.MkdirAll(canonPath, 0o755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
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

// ListEntry represents a single entry in a ListDir result.
type ListEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Mode     string `json:"mode,omitempty"`
	ModTime  string `json:"mod_time,omitempty"`
	Target   string `json:"target,omitempty"`
	Resolved string `json:"resolved,omitempty"`
	// DirPath is the display path of the directory this entry lives in, used only by the
	// text formatter to emit recursive directory headers. Never serialized to JSON.
	DirPath string `json:"-"`
	// Nlink, Uid, and Gid are populated for formatLong (long listing) parity. Not serialized.
	Nlink uint64 `json:"-"`
	Uid   string `json:"-"`
	Gid   string `json:"-"`
}

// formatLongEntry renders the long form from a walker entry, mirroring formatLong over the
// same stat-derived fields captured during the walk.
func formatLongEntry(e ListEntry) string {
	nlink := uint64(1)
	userName := "user"
	groupName := "group"
	if e.Nlink != 0 {
		nlink = e.Nlink
	}
	if e.Uid != "" {
		userName = e.Uid
	}
	if e.Gid != "" {
		groupName = e.Gid
	}
	displayName := e.Name
	if e.Target != "" {
		displayName = e.Name + " -> " + e.Target
	}
	return fmt.Sprintf("%s %d %s %s %8d %s %s\n",
		e.Mode,
		nlink,
		userName,
		groupName,
		e.Size,
		e.ModTime,
		displayName,
	)
}

func formatLong(fi os.FileInfo, name, target string) string {
	stat, sysOk := fi.Sys().(*syscall.Stat_t)
	nlink := uint64(1)
	userName := "user"
	groupName := "group"
	if sysOk {
		nlink = uint64(stat.Nlink)
		userName = strconv.FormatUint(uint64(stat.Uid), 10)
		if u, err := user.LookupId(userName); err == nil && u.Username != "" {
			userName = u.Username
		}
		groupName = strconv.FormatUint(uint64(stat.Gid), 10)
		if g, err := user.LookupGroupId(groupName); err == nil && g.Name != "" {
			groupName = g.Name
		}
	}
	displayName := name
	if target != "" {
		displayName = name + " -> " + target
	}
	return fmt.Sprintf("%s %d %s %s %8d %s %s\n",
		fi.Mode().String(),
		nlink,
		userName,
		groupName,
		fi.Size(),
		fi.ModTime().Format("Jan _2 15:04"),
		displayName,
	)
}

// walkDirEntries is the single directory traversal for ListDir. It walks readdir order
// using an explicit task queue (BFS), applying the five listing rules exactly once:
// skip dotfiles unless all; join child paths; Lstat for metadata; readlink for display;
// and recurse only into real directories (fi.IsDir() and not ModeSymlink) so a recursive
// listing never follows a symlink out of the allowlisted root.
func walkDirEntries(acc *Access, rootPath, rootDisplay string, all, recursive bool, emit func(ListEntry), visitDir ...func(displayPath string, isRoot bool)) error {
	type dirTask struct {
		absPath     string
		displayPath string
	}
	tasks := []dirTask{{absPath: rootPath, displayPath: rootDisplay}}

	for taskIdx := 0; taskIdx < len(tasks); taskIdx++ {
		cur := tasks[taskIdx]
		if len(visitDir) > 0 {
			visitDir[0](cur.displayPath, taskIdx == 0)
		}
		dirEntries, err := os.ReadDir(cur.absPath)
		if err != nil {
			return fmt.Errorf("failed to read directory %s: %w", cur.absPath, err)
		}

		var subdirs []dirTask
		for _, de := range dirEntries {
			name := de.Name()
			if !all && strings.HasPrefix(name, ".") {
				continue
			}

			fullPath := filepath.Join(cur.absPath, name)
			relPath := name
			if cur.displayPath != "" {
				relPath = filepath.Join(cur.displayPath, name)
			}

			fi, err := os.Lstat(fullPath)
			if err != nil {
				return fmt.Errorf("failed to stat %s: %w", fullPath, err)
			}

			entry := ListEntry{
				Name:    name,
				Path:    relPath,
				Size:    fi.Size(),
				Mode:    fi.Mode().String(),
				ModTime: fi.ModTime().Format("Jan _2 15:04"),
				DirPath: cur.displayPath,
			}
			if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
				entry.Nlink = uint64(stat.Nlink)
				if u, err := user.LookupId(strconv.FormatUint(uint64(stat.Uid), 10)); err == nil && u.Username != "" {
					entry.Uid = u.Username
				} else {
					entry.Uid = strconv.FormatUint(uint64(stat.Uid), 10)
				}
				if g, err := user.LookupGroupId(strconv.FormatUint(uint64(stat.Gid), 10)); err == nil && g.Name != "" {
					entry.Gid = g.Name
				} else {
					entry.Gid = strconv.FormatUint(uint64(stat.Gid), 10)
				}
			}

			switch {
			case fi.Mode()&os.ModeSymlink != 0:
				entry.Type = "symlink"
				rawTarget, err := os.Readlink(fullPath)
				if err == nil {
					entry.Target = rawTarget
					entry.Resolved = acc.resolveSymlinkEntry(fullPath, rawTarget)
				}
			case fi.IsDir():
				entry.Type = "dir"
			case fi.Mode().IsRegular():
				entry.Type = "file"
			default:
				entry.Type = "other"
			}

			emit(entry)

			if recursive && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 {
				subDisplay := name
				if cur.displayPath != "" {
					subDisplay = filepath.Join(cur.displayPath, name)
				}
				subdirs = append(subdirs, dirTask{absPath: fullPath, displayPath: subDisplay})
			}
		}

		if recursive {
			tasks = append(tasks, subdirs...)
		}
	}
	return nil
}

func walkDirJSON(acc *Access, rootPath, rootDisplay string, all, recursive bool, entries *[]ListEntry) error {
	return walkDirEntries(acc, rootPath, rootDisplay, all, recursive, func(e ListEntry) {
		*entries = append(*entries, e)
	})
}

// walkDirText renders a listing from the shared walker. Long form reuses formatLong; the
// short form prints bare names (with symlink target) like a plain `ls`. Recursive mode
// emits one directory header block per directory, in BFS visit order, including headers
// for empty directories.
func walkDirText(acc *Access, rootPath, rootDisplay string, long, all, recursive bool) (string, error) {
	var b strings.Builder
	sawRootHeader := false
	visit := func(displayPath string, isRoot bool) {
		if !recursive {
			return
		}
		if !sawRootHeader {
			fmt.Fprintf(&b, "%s:\n", displayPath)
			sawRootHeader = true
			return
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "%s:\n", displayPath)
	}
	err := walkDirEntries(acc, rootPath, rootDisplay, all, recursive, func(e ListEntry) {
		if long {
			b.WriteString(formatLongEntry(e))
		} else {
			if e.Target != "" {
				fmt.Fprintf(&b, "%s -> %s\n", e.Name, e.Target)
			} else {
				fmt.Fprintf(&b, "%s\n", e.Name)
			}
		}
	}, visit)
	if err != nil {
		return "", err
	}
	return b.String(), nil
}

// ListDir inspects path or lists directory contents natively using os.ReadDir,
// os.Lstat, and os.Readlink, supporting structured symlink metadata.
func ListDir(acc *Access, path, cwd string, long, all, recursive, asJSON bool) (string, error) {
	canonPath, err := acc.ResolveNoFollow(path, cwd, false)
	if err != nil {
		return "", err
	}

	fi, err := os.Lstat(canonPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat %s: %w", path, err)
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		rawTarget, err := os.Readlink(canonPath)
		if err != nil {
			return "", fmt.Errorf("failed to readlink %s: %w", canonPath, err)
		}
		resolved := acc.resolveSymlinkEntry(canonPath, rawTarget)
		entry := ListEntry{
			Name:     filepath.Base(path),
			Path:     path,
			Type:     "symlink",
			Size:     fi.Size(),
			Mode:     fi.Mode().String(),
			ModTime:  fi.ModTime().Format("Jan _2 15:04"),
			Target:   rawTarget,
			Resolved: resolved,
		}
		if asJSON {
			data, err := json.MarshalIndent([]ListEntry{entry}, "", "  ")
			if err != nil {
				return "", err
			}
			return string(data) + "\n", nil
		}
		if long {
			return formatLong(fi, entry.Name, entry.Target), nil
		}
		return entry.Name + " -> " + entry.Target + "\n", nil
	}

	if !fi.IsDir() {
		entry := ListEntry{
			Name:    filepath.Base(path),
			Path:    path,
			Type:    "file",
			Size:    fi.Size(),
			Mode:    fi.Mode().String(),
			ModTime: fi.ModTime().Format("Jan _2 15:04"),
		}
		if asJSON {
			data, err := json.MarshalIndent([]ListEntry{entry}, "", "  ")
			if err != nil {
				return "", err
			}
			return string(data) + "\n", nil
		}
		if long {
			return formatLong(fi, entry.Name, ""), nil
		}
		return entry.Name + "\n", nil
	}

	if asJSON {
		var entries []ListEntry
		if err := walkDirJSON(acc, canonPath, "", all, recursive, &entries); err != nil {
			return "", err
		}
		if len(entries) == 0 {
			return "[]\n", nil
		}
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return "", err
		}
		return string(data) + "\n", nil
	}

	return walkDirText(acc, canonPath, path, long, all, recursive)
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
