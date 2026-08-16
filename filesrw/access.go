// Package filesrw implements a standalone read/write/edit/patch/list file
// tool for AI agents, gated by a per-directory FILES_RW_ACCESS allowlist.
package filesrw

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	// AccessFileName is the exact filename (no upward search) that grants file
	// access for the current directory. Its own path is always denied for write/mutation.
	AccessFileName = "FILES_RW_ACCESS"

	rulePrefixWrite = "w:"
	rulePrefixRead  = "r:"
	tildeChar       = "~"
)

// Access is the parsed, resolved set of access rules from one
// FILES_RW_ACCESS file. All roots are canonical absolute paths (symlinks
// resolved) so containment checks are exact.
type Access struct {
	writableRoots []string
	readableRoots []string // superset of writableRoots
	denyPath      string   // FILES_RW_ACCESS's own canonical path
	denyFileInfo  os.FileInfo
}

// LoadAccess reads and parses <cwd>/FILES_RW_ACCESS. Returns an error
// (access must be denied entirely) if the file is missing, unreadable, or
// contains an invalid rule - there is no partial-trust fallback.
func LoadAccess(cwd string) (*Access, error) {
	accessFilePath := filepath.Join(cwd, AccessFileName)

	f, err := os.Open(accessFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no %s file in %s - all file access is denied by default", AccessFileName, cwd)
		}
		return nil, fmt.Errorf("failed to read %s: %w", AccessFileName, err)
	}
	defer f.Close()

	denyFileInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat %s: %w", AccessFileName, err)
	}

	denyPath, err := filepath.EvalSymlinks(accessFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s's own path: %w", AccessFileName, err)
	}

	acc := &Access{
		denyPath:     denyPath,
		denyFileInfo: denyFileInfo,
	}

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var writable bool
		var rest string
		switch {
		case strings.HasPrefix(line, rulePrefixWrite):
			writable = true
			rest = strings.TrimSpace(line[len(rulePrefixWrite):])
		case strings.HasPrefix(line, rulePrefixRead):
			writable = false
			rest = strings.TrimSpace(line[len(rulePrefixRead):])
		default:
			return nil, fmt.Errorf("%s line %d: invalid rule %q - must start with %q or %q", AccessFileName, lineNo, line, rulePrefixWrite, rulePrefixRead)
		}
		if rest == "" {
			return nil, fmt.Errorf("%s line %d: rule has no path", AccessFileName, lineNo)
		}

		root, err := canonicalizeRoot(rest, cwd, writable)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", AccessFileName, lineNo, err)
		}

		acc.readableRoots = append(acc.readableRoots, root)
		if writable {
			acc.writableRoots = append(acc.writableRoots, root)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", AccessFileName, err)
	}

	return acc, nil
}

// Summary formats a's granted permissions for an agent to read directly,
// according to D42 - read-write roots, read-only roots (readableRoots minus
// writableRoots, not the raw superset relationship the struct stores
// internally), and a note that FILES_RW_ACCESS's own path is always denied
// for writes regardless of the rules below.
func (a *Access) Summary() string {
	writable := make(map[string]bool, len(a.writableRoots))
	for _, root := range a.writableRoots {
		writable[root] = true
	}

	var readOnly []string
	for _, root := range a.readableRoots {
		if !writable[root] {
			readOnly = append(readOnly, root)
		}
	}

	var b strings.Builder
	b.WriteString("Read-write:\n")
	if len(a.writableRoots) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, root := range a.writableRoots {
		fmt.Fprintf(&b, "  %s\n", root)
	}

	b.WriteString("Read-only:\n")
	if len(readOnly) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, root := range readOnly {
		fmt.Fprintf(&b, "  %s\n", root)
	}

	fmt.Fprintf(&b, "\nNote: %s itself (%s) is always denied for write access, regardless of the rules above.\n", AccessFileName, a.denyPath)

	return b.String()
}

// canonicalizeRoot resolves a FILES_RW_ACCESS rule's path to a canonical
// absolute path. A r: root must exist; a w: root may not exist yet, in which case
// its existing ancestor directory is canonicalized.
func canonicalizeRoot(path, cwd string, writable bool) (string, error) {
	if strings.Contains(path, tildeChar) {
		return "", fmt.Errorf("path %q contains %q - not supported, use an absolute path", path, tildeChar)
	}
	if writable {
		return canonicalizeTarget(path, cwd)
	}
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %q: %w", path, err)
	}
	return resolved, nil
}

// canonicalizeTarget resolves a request path (possibly relative to cwd) to
// a canonical absolute path, for use in an access-control decision. Symlinks
// are resolved for as much of the path as actually exists on disk - so a
// not-yet-existing write target still has its real (symlink-resolved)
// ancestor directory checked, while the not-yet-existing tail is trusted as
// given relative to that resolved ancestor.
func canonicalizeTarget(path, cwd string) (string, error) {
	if strings.Contains(path, tildeChar) {
		return "", fmt.Errorf("path %q contains %q - not supported, use an absolute path", path, tildeChar)
	}
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	abs = filepath.Clean(abs)

	dir := abs
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(dir)
		if err == nil {
			full := resolved
			for i := len(tail) - 1; i >= 0; i-- {
				full = filepath.Join(full, tail[i])
			}
			return full, nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("failed to resolve %q: %w", path, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("failed to resolve %q: no existing ancestor directory found", path)
		}
		tail = append(tail, filepath.Base(dir))
		dir = parent
	}
}

// withinRoot reports whether path is root itself or a descendant of it,
// using a path-separator-aware boundary check (a naive string prefix would
// wrongly match "/home/bob/Downloads-secret" against root "/home/bob/Downloads").
func withinRoot(path, root string) bool {
	if path == root {
		return true
	}
	rootWithSep := root
	if !strings.HasSuffix(rootWithSep, string(os.PathSeparator)) {
		rootWithSep += string(os.PathSeparator)
	}
	return strings.HasPrefix(path, rootWithSep)
}

func getNlinkAndDevIno(info os.FileInfo) (nlink uint64, dev uint64, ino uint64, ok bool) {
	if info == nil {
		return 0, 0, 0, false
	}
	stat, sysOk := info.Sys().(*syscall.Stat_t)
	if !sysOk {
		return 0, 0, 0, false
	}
	return uint64(stat.Nlink), uint64(stat.Dev), uint64(stat.Ino), true
}

func (a *Access) checkHardlinkSafety(info os.FileInfo, needWrite bool) error {
	if info == nil || info.IsDir() {
		return nil
	}

	// Check if this inode matches FILES_RW_ACCESS
	if a.denyFileInfo != nil && os.SameFile(info, a.denyFileInfo) {
		if needWrite {
			return fmt.Errorf("access to %s itself is always denied", AccessFileName)
		}
		return nil
	}

	nlink, _, _, ok := getNlinkAndDevIno(info)
	if ok && nlink > 1 {
		return fmt.Errorf("hardlink target has %d links - access denied for multi-linked files", nlink)
	}
	return nil
}

// OpenFile validates path (relative to cwd) against a's access rules, opens the target
// file descriptor atomically, and verifies file identity and hardlink safety on the open handle.
func (a *Access) OpenFile(path, cwd string, needWrite bool, flag int, perm os.FileMode) (*os.File, string, error) {
	canon, err := canonicalizeTarget(path, cwd)
	if err != nil {
		return nil, "", err
	}

	roots := a.readableRoots
	verb, rule := "read", "r:"
	if needWrite {
		roots = a.writableRoots
		verb, rule = "write", "w:"
	}

	isAllowedRoot := false
	for _, root := range roots {
		if withinRoot(canon, root) {
			isAllowedRoot = true
			break
		}
	}
	if !isAllowedRoot {
		return nil, "", fmt.Errorf("%s access denied for %q - not covered by any %q rule in %s", verb, path, rule, AccessFileName)
	}

	f, err := os.OpenFile(canon, flag, perm)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open %s: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, "", fmt.Errorf("failed to stat open file %s: %w", path, err)
	}

	if a.denyFileInfo != nil && os.SameFile(info, a.denyFileInfo) {
		if needWrite {
			f.Close()
			return nil, "", fmt.Errorf("access to %s itself is always denied", AccessFileName)
		}
		return f, canon, nil
	}

	if err := a.checkHardlinkSafety(info, needWrite); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("access denied for %q: %w", path, err)
	}

	return f, canon, nil
}

// Resolve validates path (relative to cwd) against a's rules and returns its
// canonical form on success. needWrite selects which rule set (w: vs r:/w:)
// must cover it. FILES_RW_ACCESS's own path is denied for writing/mutation.
func (a *Access) Resolve(path, cwd string, needWrite bool) (string, error) {
	canon, err := canonicalizeTarget(path, cwd)
	if err != nil {
		return "", err
	}

	if canon == a.denyPath {
		if needWrite {
			return "", fmt.Errorf("access to %s itself is always denied", AccessFileName)
		}
		return canon, nil
	}

	roots := a.readableRoots
	verb, rule := "read", "r:"
	if needWrite {
		roots = a.writableRoots
		verb, rule = "write", "w:"
	}
	for _, root := range roots {
		if withinRoot(canon, root) {
			if info, err := os.Stat(canon); err == nil {
				if err := a.checkHardlinkSafety(info, needWrite); err != nil {
					return "", fmt.Errorf("access denied for %q: %w", path, err)
				}
			}
			return canon, nil
		}
	}
	return "", fmt.Errorf("%s access denied for %q - not covered by any %q rule in %s", verb, path, rule, AccessFileName)
}
