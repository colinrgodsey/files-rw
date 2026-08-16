# files-rw

A per-directory, allowlist-gated file read/write/edit/patch/copy/move/delete/list/tail/append tool, built for giving AI agents real filesystem access without handing them an unrestricted shell.

Every invocation reads `FILES_RW_ACCESS` from the current working directory. No file, no access - there's no partial-trust fallback. Missing, unreadable, or invalid means everything is denied.

```
# FILES_RW_ACCESS
r: ../shared-docs
w: .
w: output
```

- `r:` grants read-only access to a directory (and everything under it).
- `w:` grants read-write access.
- Blank lines and `#` comments are ignored.
- Paths are relative to `FILES_RW_ACCESS`'s own directory, resolved to canonical absolute paths (symlinks included) so containment checks can't be fooled by a symlink or hardlink pointing outside the granted roots.
- `FILES_RW_ACCESS` can never be written to via `files-rw`, regardless of what rules it grants - only read.

Run `files-rw access` from inside a directory to see exactly what it currently grants, rather than guessing from `read`/`write` error messages.

## Commands

`read`, `write`, `edit`, `patch`, `copy`, `move`, `delete`, `list`, `tail`, `append`, `access` - each documented via `files-rw <command> --help`. There's no separate directory-creation command: `write` and `append` both create missing parent directories as a side effect.

## Build

```bash
go build -o files-rw .
```

## Origin and security testing

This started as part of [wackypub](https://github.com/colinrgodsey/wackypub), a folder-based AI agent CLI/SDK, and is vendored there as a git submodule (`tools/files-rw`) - that's still where the project's shared process lives: security testing methodology ([`docs/SWARM_TESTING.md`](https://github.com/colinrgodsey/wackypub/blob/main/docs/SWARM_TESTING.md)), the pass/fail checklist ([`.agents/SECURITY_TESTING.md`](https://github.com/colinrgodsey/wackypub/blob/main/.agents/SECURITY_TESTING.md)), and the full decision history ([`.agents/DECISIONS.md`](https://github.com/colinrgodsey/wackypub/blob/main/.agents/DECISIONS.md)).

## License

MIT
