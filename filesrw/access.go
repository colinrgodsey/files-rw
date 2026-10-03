// Package filesrw implements a standalone read/write/edit/patch/list file
// tool for AI agents, gated by a per-directory FILES_RW_ACCESS allowlist.
package filesrw

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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

	// MaxSymlinkHops is the maximum number of symlink hops to follow (D86).
	MaxSymlinkHops = 8
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

// isAccessFile returns true if the provided canonical path is the path of the
// FILES_RW_ACCESS file itself.
func (a *Access) isAccessFile(canonPath string) bool {
	return canonPath == a.denyPath
}

// warnIgnoredRule reports one unusable FILES_RW_ACCESS rule and states the
// consequence, so a partially applied ACL is never mistaken for the intended one.
// warnPendingRule reports a well-formed grant whose path is not on disk yet. It is kept
// and will apply as soon as the path appears, but a typo and a not-yet-created file look
// identical in a grant list, so the operator hears about it either way.
func warnPendingRule(lineNo int, line string) {
	fmt.Fprintf(accessWarnings, "warning: %s line %d (%q): path does not exist yet - grant kept and will apply once it exists, check the spelling if that is not what you meant\n", AccessFileName, lineNo, line)
}

func warnIgnoredRule(lineNo int, line, reason string) {
	fmt.Fprintf(accessWarnings, "warning: %s line %d (%q): %s - rule ignored, remaining rules still apply\n", AccessFileName, lineNo, line, reason)
}

// accessWarnings receives per-rule problems found while reading FILES_RW_ACCESS.
// A broken line must not take the rest of the ACL down with it, so these are reported
// rather than returned, and the loader runs once per invocation, so an operator sees
// the warning every time instead of once at setup. It is a variable so a test can
// assert the exact text an operator would get.
var accessWarnings io.Writer = os.Stderr

// MaxACLLineBytes bounds how much of a single FILES_RW_ACCESS line is read. A line
// past this is not a rule, it is a stray paste, and it must not take the rest of the
// grant list down with it.
const MaxACLLineBytes = 64 * 1024

// aclLine is one physical line of FILES_RW_ACCESS with its position. tooLong marks a
// line that was longer than MaxACLLineBytes: its remainder was discarded and the rule
// is unusable, but the lines after it are still read.
type aclLine struct {
	no      int
	raw     string
	tooLong bool
}

// clipForWarning shortens a rule for warning text without echoing a huge paste.
func clipForWarning(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 48 {
		return s
	}
	return s[:48] + "..."
}

// readACLLines splits the access file into physical lines without ever failing on the
// content of a line. The previous bufio.Scanner aborted the whole file at 64KB, which
// turned one pathological line into deny-all; here the over-long line is marked instead.
func readACLLines(r io.Reader) ([]aclLine, error) {
	reader := bufio.NewReaderSize(r, MaxACLLineBytes)
	var out []aclLine
	lineNo := 0
	for {
		rawBytes, err := reader.ReadSlice('\n')
		tooLong := errors.Is(err, bufio.ErrBufferFull)
		for errors.Is(err, bufio.ErrBufferFull) {
			_, drainErr := reader.ReadSlice('\n')
			if drainErr == nil || !errors.Is(drainErr, bufio.ErrBufferFull) {
				err = drainErr
				break
			}
		}
		raw := string(rawBytes)
		if raw == "" && err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		lineNo++
		out = append(out, aclLine{no: lineNo, raw: raw, tooLong: tooLong})
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if errors.Is(err, io.EOF) {
			return out, nil
		}
	}
}

// LoadAccess reads and parses <cwd>/FILES_RW_ACCESS. Only a whole-file problem
// denies access: a missing, unreadable, or partially unreadable file yields an
// error and no grants. Individual rules are independent. A rule that cannot be
// used, because it is malformed or its path cannot be resolved, is reported on
// accessWarnings and skipped, never fatal, so one typo cannot revoke the grants
// of every other line in the file.
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

	denyPath, _, _, err := evalSymlinksHops(accessFilePath, MaxSymlinkHops)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s's own path: %w", AccessFileName, err)
	}

	acc := &Access{
		denyPath:     denyPath,
		denyFileInfo: denyFileInfo,
	}

	entries, err := readACLLines(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", AccessFileName, err)
	}
	for _, entry := range entries {
		lineNo := entry.no
		if entry.tooLong {
			warnIgnoredRule(lineNo, clipForWarning(entry.raw), fmt.Sprintf("line exceeds %d bytes - not a rule anyone typed", MaxACLLineBytes))
			continue
		}
		line := strings.TrimSpace(entry.raw)
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
			warnIgnoredRule(lineNo, line, fmt.Sprintf("invalid rule %q - must start with %q or %q", line, rulePrefixWrite, rulePrefixRead))
			continue
		}
		if rest == "" {
			warnIgnoredRule(lineNo, line, "rule has no path")
			continue
		}

		// A path that does not exist yet is a valid grant, not a configuration error:
		// declaring write access to a file the agent intends to create is the normal
		// case. Whatever exists on disk is symlink-resolved and the missing tail is kept
		// literally, so the root compares equal to the operation target once the path
		// appears. A read root for a missing path is inert for the same reason.
		root, err := canonicalizeTarget(rest, cwd)
		if err != nil {
			warnIgnoredRule(lineNo, line, err.Error())
			continue
		}
		if _, statErr := os.Stat(root); statErr != nil && os.IsNotExist(statErr) {
			warnPendingRule(lineNo, line)
		}

		acc.readableRoots = append(acc.readableRoots, root)
		if writable {
			acc.writableRoots = append(acc.writableRoots, root)
		}
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

// evalSymlinksHops resolves symlinks in path up to maxHops.
// If hops exceeds maxHops, an error is returned (chain cap / cycle detection).
// If a symlink in the chain points to a non-existent target, isDangling is true and os.ErrNotExist is returned.
// If path (or an ancestor) simply does not exist without involving a symlink, isDangling is false and os.ErrNotExist is returned.
func evalSymlinksHops(path string, maxHops int) (string, int, bool, error) {
	if !filepath.IsAbs(path) {
		return "", 0, false, fmt.Errorf("path must be absolute: %q", path)
	}
	path = filepath.Clean(path)

	hops := 0
	current := "/"
	parts := strings.Split(path, string(os.PathSeparator))

	for i := 0; i < len(parts); i++ {
		comp := parts[i]
		if comp == "" || comp == "." {
			continue
		}
		if comp == ".." {
			current = filepath.Dir(current)
			continue
		}

		candidate := filepath.Join(current, comp)
		fi, err := os.Lstat(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				return candidate, hops, false, os.ErrNotExist
			}
			return "", hops, false, err
		}

		if fi.Mode()&os.ModeSymlink != 0 {
			hops++
			if hops > maxHops {
				return "", hops, false, fmt.Errorf("symlink chain exceeded maximum of %d hops", maxHops)
			}
			target, err := os.Readlink(candidate)
			if err != nil {
				return "", hops, false, err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(candidate), target)
			}
			target = filepath.Clean(target)

			if _, err := os.Lstat(target); err != nil {
				if os.IsNotExist(err) {
					return target, hops, true, os.ErrNotExist
				}
				return "", hops, false, err
			}

			remaining := parts[i+1:]
			newPath := target
			for _, r := range remaining {
				if r != "" {
					newPath = filepath.Join(newPath, r)
				}
			}

			current = "/"
			parts = strings.Split(newPath, string(os.PathSeparator))
			i = -1
			continue
		}

		current = candidate
	}

	return filepath.Clean(current), hops, false, nil
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

	resolved, _, isDangling, err := evalSymlinksHops(abs, MaxSymlinkHops)
	if err == nil {
		return resolved, nil
	}
	if isDangling {
		return "", fmt.Errorf("cannot resolve %q: dangling symlink points to non-existent target", path)
	}
	if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to resolve %q: %w", path, err)
	}

	dir := abs
	var tail []string
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("failed to resolve %q: no existing ancestor directory found", path)
		}
		tail = append(tail, filepath.Base(dir))
		dir = parent

		resDir, _, dirDangling, dirErr := evalSymlinksHops(dir, MaxSymlinkHops)
		if dirErr == nil {
			full := resDir
			for i := len(tail) - 1; i >= 0; i-- {
				full = filepath.Join(full, tail[i])
			}
			return full, nil
		}
		if dirDangling {
			return "", fmt.Errorf("cannot resolve %q: ancestor directory contains dangling symlink", path)
		}
		if !os.IsNotExist(dirErr) {
			return "", fmt.Errorf("failed to resolve %q: %w", path, dirErr)
		}
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

	// Check for FILES_RW_ACCESS self-read bypass first.
	if a.isAccessFile(canon) {
		if needWrite {
			return nil, "", fmt.Errorf("access to %s itself is always denied", AccessFileName)
		}
		// If it's a read, we bypass the root check.
	} else {
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

// IsWritable reports whether canonPath is within any writable root in a,
// and is not FILES_RW_ACCESS itself.
func (a *Access) IsWritable(canonPath string) bool {
	if canonPath == a.denyPath {
		return false
	}
	for _, root := range a.writableRoots {
		if withinRoot(canonPath, root) {
			return true
		}
	}
	return false
}

// Resolve validates path (relative to cwd) against a's rules and returns its
// canonical form on success. needWrite selects which rule set (w: vs r:/w:)
// must cover it. FILES_RW_ACCESS's own path is denied for writing/mutation.
func (a *Access) Resolve(path, cwd string, needWrite bool) (string, error) {
	canon, err := canonicalizeTarget(path, cwd)
	if err != nil {
		return "", err
	}

	if a.isAccessFile(canon) {
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

// ResolveNoFollow validates path (relative to cwd) against a's access rules,
// resolving symlinks in ancestor directories but NOT following the final
// component if it is a symlink. Used for delete and symlink creation.
func (a *Access) ResolveNoFollow(path, cwd string, needWrite bool) (string, error) {
	if strings.Contains(path, tildeChar) {
		return "", fmt.Errorf("path %q contains %q - not supported, use an absolute path", path, tildeChar)
	}
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	abs = filepath.Clean(abs)

	dir := filepath.Dir(abs)
	base := filepath.Base(abs)

	canonDir, err := canonicalizeTarget(dir, cwd)
	if err != nil {
		return "", err
	}
	canonPath := filepath.Join(canonDir, base)

	if a.isAccessFile(canonPath) {
		if needWrite {
			return "", fmt.Errorf("access to %s itself is always denied", AccessFileName)
		}
		return canonPath, nil
	}

	roots := a.readableRoots
	verb, rule := "read", "r:"
	if needWrite {
		roots = a.writableRoots
		verb, rule = "write", "w:"
	}
	for _, root := range roots {
		if withinRoot(canonPath, root) {
			if info, err := os.Lstat(canonPath); err == nil {
				if info.Mode()&os.ModeSymlink == 0 {
					if err := a.checkHardlinkSafety(info, needWrite); err != nil {
						return "", fmt.Errorf("access denied for %q: %w", path, err)
					}
				}
			}
			return canonPath, nil
		}
	}
	return "", fmt.Errorf("%s access denied for %q - not covered by any %q rule in %s", verb, path, rule, AccessFileName)
}

// ResolveSymlinkCreation validates that the caller has write access at linkPath
// (the source) and read coverage at target (the destination), per D86.
// Confinement is coverage-based, not existence-based: dangling links are
// allowed if their target falls inside a read-granted root.
func (a *Access) ResolveSymlinkCreation(linkPath, target, cwd string) (string, error) {
	canonLink, err := a.ResolveNoFollow(linkPath, cwd, true)
	if err != nil {
		return "", err
	}

	if strings.Contains(target, tildeChar) {
		return "", fmt.Errorf("target %q contains %q - not supported, use an absolute path", target, tildeChar)
	}

	var targetAbs string
	if filepath.IsAbs(target) {
		targetAbs = target
	} else {
		targetAbs = filepath.Join(filepath.Dir(canonLink), target)
	}
	targetAbs = filepath.Clean(targetAbs)

	resolvedTarget, hops, _, err := evalSymlinksHops(targetAbs, MaxSymlinkHops)
	if hops > MaxSymlinkHops {
		return "", fmt.Errorf("symlink target %q chain exceeded maximum of %d hops", target, MaxSymlinkHops)
	}

	var canonTarget string
	if err == nil {
		canonTarget = resolvedTarget
	} else if os.IsNotExist(err) {
		dir := resolvedTarget
		var tail []string
		for {
			resDir, dirHops, _, dirErr := evalSymlinksHops(dir, MaxSymlinkHops)
			if dirErr == nil && dirHops <= MaxSymlinkHops {
				canonTarget = resDir
				for i := len(tail) - 1; i >= 0; i-- {
					canonTarget = filepath.Join(canonTarget, tail[i])
				}
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				canonTarget = resolvedTarget
				break
			}
			tail = append(tail, filepath.Base(dir))
			dir = parent
		}
	} else {
		return "", fmt.Errorf("failed to resolve symlink target %q: %w", target, err)
	}

	covered := false
	for _, root := range a.readableRoots {
		if withinRoot(canonTarget, root) {
			covered = true
			break
		}
	}
	if !covered {
		return "", fmt.Errorf("read access denied for symlink target %q - not covered by any %q rule in %s", target, rulePrefixRead, AccessFileName)
	}

	return canonLink, nil
}

// resolveSymlinkEntry determines the resolved state of a symlink for ListDir.
// Three states:
// (a) target missing/dangling inside a read-granted root -\u003e \"dangling\"
// (b) target outside every granted root / not reachable -\u003e \"blocked\" (never the path)
// (c) present and reachable inside a read-granted root -\u003e canonical resolved path
func (a *Access) resolveSymlinkEntry(entryFullPath, rawTarget string) string {
	targetAbs := rawTarget
	if !filepath.IsAbs(targetAbs) {
		targetAbs = filepath.Join(filepath.Dir(entryFullPath), rawTarget)
	}
	targetAbs = filepath.Clean(targetAbs)

	canonResolved, hops, _, err := evalSymlinksHops(targetAbs, MaxSymlinkHops)
	if err != nil {
		if hops > MaxSymlinkHops {
			return "blocked"
		}
		if os.IsNotExist(err) {
			targetCovered := false
			dir := canonResolved
			var tail []string
			for {
				resDir, _, _, dirErr := evalSymlinksHops(dir, MaxSymlinkHops)
				if dirErr == nil {
					canonAncestor := resDir
					for i := len(tail) - 1; i >= 0; i-- {
						canonAncestor = filepath.Join(canonAncestor, tail[i])
					}
					for _, root := range a.readableRoots {
						if withinRoot(canonAncestor, root) {
							targetCovered = true
							break
						}
					}
					break
				}
				parent := filepath.Dir(dir)
				if parent == dir {
					break
				}
				tail = append(tail, filepath.Base(dir))
				dir = parent
			}
			if targetCovered {
				return "dangling"
			}
			return "blocked"
		}
		return "blocked"
	}

	for _, root := range a.readableRoots {
		if withinRoot(canonResolved, root) {
			return canonResolved
		}
	}
	return "blocked"
}
