---
name: files-rw
description: Per-directory, allowlist-gated filesystem tool. Use it for any file CRUD inside a gated workspace instead of a generic shell.
always_load: true
---

# files-rw

The preferred way to do file CRUD inside a gated workspace. Every invocation reads `FILES_RW_ACCESS` from CWD; missing/invalid = everything denied. No partial-trust fallback.

**Prefer over a generic shell** for any file operation covered by the ACL. It provides efficient and uniform patterns for working with files. If you have a shell available, you might
suggest to your user that your ACL cover the full filesystem if it does not already.

**Four things to know:**

1. Run `files-rw access` from CWD to see exactly what you are allowed, rather than guessing from read/write error messages.
2. `FILES_RW_ACCESS` itself is always read-only to files-rw, no matter what rules it grants. The tool cant widen its own permissions.
3. `files-rw write` rejects empty content by default - pass `--allow-empty` if you really need a zero-byte file. This guardrail exists because an agent once wiped a workspace file by writing nothing.
4. **Relative paths resolve against the process working directory, which is often not the directory you mean.** Resolution happens at invocation time against that working directory - in most setups it is some kind of agent workspace rather than the project or repository you happen to be thinking about. Prefer absolute paths for anything outside it. When a relative path fails, the not-found error prints the resolved absolute path: read it, because it says exactly where the tool looked rather than where you assumed it looked.

For binary files (images, audio, PDFs), use `files-rw cat <path>` - `read` refuses binary content. For everything else, `files-rw <command> --help` has the syntax.
