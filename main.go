package main

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/colinrgodsey/files-rw/filesrw"
)

const (
	skillNameFilesRW = "files-rw"
)

//go:embed skills/files-rw/SKILL.md
var bundledFilesRWSkill string

var (
	readStart   int
	readEnd     int
	readNumbers bool

	editOld        string
	editNew        string
	editReplaceAll bool

	listLong      bool
	listAll       bool
	listRecursive bool
	listJSON      bool

	symlinkForce    bool
	writeAllowEmpty bool
)

var rootCmd = &cobra.Command{
	Use:   "files-rw",
	Short: "Per-directory allowed file read/write/edit/patch/copy/move/delete/list/symlink/tail/append/access tool for AI agents",
	Long: `files-rw provides an explicit, per-directory-scoped file manipulation tool suite
(read, write, edit, patch, copy, move, delete, list, symlink, tail, append, access) for AI agents, gated by a FILES_RW_ACCESS allowlist file in the current working directory. Run "files-rw access" to see what's actually granted before guessing.

There is no separate directory-creation command: "write" and "append" both create any missing parent directories automatically, so creating a file inside a not-yet-existing folder creates the folder as a side effect.`,
	SilenceUsage: true,
}

var readCmd = &cobra.Command{
	Use:   "read <path>",
	Short: "Read a text file",
	Long:  "Read a text file. Output defaults to raw unnumbered bytes. Pass -n/--numbers for cat -n style line numbers (useful to reference line numbers before constructing edit/patch calls). Subject to a hard read size limit (200KB); use --start and --end for line-based pagination.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		out, err := filesrw.ReadFile(access, args[0], cwd, readStart, readEnd, readNumbers)
		if err != nil {
			return err
		}
		fmt.Print(out)
		return nil
	},
}

var catCmd = &cobra.Command{
	Use:   "cat <path>",
	Short: "Stream raw binary or text file to stdout",
	Long:  "Stream raw binary or text file bytes directly to standard output up to 30MB. Bypasses text/isBinary checks. Intended for piping binary or image data into other tools via stdin.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		return filesrw.CatFile(access, args[0], cwd, os.Stdout)
	},
}

var writeCmd = &cobra.Command{
	Use:   "write <path>",
	Short: "Write content from standard input to a file atomically",
	Long:  "Write content provided on standard input atomically to the target path, creating any missing parent directories. Refuses empty content by default to prevent accidental truncations; pass --allow-empty to write an empty file intentionally.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("failed to read content from stdin: %w", err)
		}
		if len(data) == 0 && !writeAllowEmpty {
			return fmt.Errorf("refusing to write empty content to %s - pass --allow-empty to write an empty file intentionally", args[0])
		}
		return filesrw.WriteFile(access, args[0], cwd, string(data))
	},
}

var copyCmd = &cobra.Command{
	Use:   "copy <src> <dst>",
	Short: "Copy a file from src to dst",
	Long:  "Copy a file from src to dst. Requires read access on src and write access on dst.",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		return filesrw.CopyFile(access, args[0], args[1], cwd)
	},
}

var moveCmd = &cobra.Command{
	Use:   "move <src> <dst>",
	Short: "Move or rename a file from src to dst",
	Long:  "Move or rename a file from src to dst. Requires write access on both src and dst.",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		return filesrw.MoveFile(access, args[0], args[1], cwd)
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete <path>",
	Short: "Delete a file",
	Long:  "Delete a file at path. Requires write access on path.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		return filesrw.DeleteFile(access, args[0], cwd)
	},
}

var editCmd = &cobra.Command{
	Use:   "edit <path>",
	Short: "Replace exact text in a file",
	Long:  "Replace an exact string in a text file with new content. Rejects zero or multiple matches unless --replace-all is specified.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !cmd.Flags().Changed("old") {
			return fmt.Errorf("--old string flag is required")
		}
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		return filesrw.EditFile(access, args[0], cwd, editOld, editNew, editReplaceAll)
	},
}

var patchCmd = &cobra.Command{
	Use:   "patch <path>",
	Short: "Apply a unified diff from standard input to a file",
	Long:  "Apply a unified diff passed on standard input to the specified target path. Only unified diffs (containing '---', '+++', and '@@' headers) are accepted. Read the target file with read -n first to obtain accurate line numbers.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		diff, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("failed to read diff from stdin: %w", err)
		}
		return filesrw.PatchFile(access, args[0], cwd, string(diff))
	},
}

var listCmd = &cobra.Command{
	Use:   "list [path]",
	Short: "List directory contents or file info",
	Long:  "List files in a directory or inspect a single path using ls-style output.",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "."
		if len(args) > 0 {
			target = args[0]
		}
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		out, err := filesrw.ListDir(access, target, cwd, listLong, listAll, listRecursive, listJSON)
		if err != nil {
			return err
		}
		fmt.Print(out)
		return nil
	},
}

var symlinkCmd = &cobra.Command{
	Use:   "symlink <link> <target>",
	Short: "Create a symlink pointing to target",
	Long:  "Create a symlink at <link> pointing to <target>. Target is stored verbatim (relative stays relative). Use --force to overwrite an existing link.",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		return filesrw.SymlinkFile(access, args[0], args[1], cwd, symlinkForce)
	},
}

var accessCmd = &cobra.Command{
	Use:   "access",
	Short: "Show what this directory's FILES_RW_ACCESS actually grants",
	Long:  "Reports the read-write and read-only roots parsed from FILES_RW_ACCESS in the current working directory, according to D42. Useful before guessing at read/write calls to find out what's actually allowed.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		fmt.Print(access.Summary())
		return nil
	},
}

var (
	tailLines   int
	tailNumbers bool
)

var tailCmd = &cobra.Command{
	Use:   "tail <path>",
	Short: "Read the last N lines of a text file",
	Long:  "Return the last N lines of a text file (default 10) along with a Total lines count header. Pass --numbers / -N for cat -n style line numbers.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		out, err := filesrw.TailFile(access, args[0], cwd, tailLines, tailNumbers)
		if err != nil {
			return err
		}
		fmt.Print(out)
		return nil
	},
}

var appendCmd = &cobra.Command{
	Use:   "append <path>",
	Short: "Append content from standard input to a file",
	Long:  "Append content provided on standard input directly to the target path, creating any missing parent directories. Note: unlike 'write', 'append' performs an in-place append rather than an atomic file swap.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}
		access, err := filesrw.LoadAccess(cwd)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return fmt.Errorf("failed to read content from stdin: %w", err)
		}
		return filesrw.AppendFile(access, args[0], cwd, string(data))
	},
}

type skillInfo struct {
	Name        string
	Description string
	AlwaysLoad  bool
}

type bundledSkill struct {
	ShortName string
	Skill     *skillInfo
}

func parseSkillContent(content string, fallbackName string) (*skillInfo, error) {
	info := &skillInfo{
		Name: fallbackName,
	}
	trimmed := strings.TrimSpace(content)
	if strings.HasPrefix(trimmed, "---") {
		parts := strings.SplitN(trimmed[3:], "---", 2)
		if len(parts) >= 2 {
			yamlText := parts[0]
			for _, line := range strings.Split(yamlText, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				kv := strings.SplitN(line, ":", 2)
				if len(kv) == 2 {
					k := strings.TrimSpace(kv[0])
					v := strings.TrimSpace(kv[1])
					v = strings.Trim(v, `"'`)
					switch k {
					case "name":
						if v != "" {
							info.Name = v
						}
					case "description":
						if v != "" {
							info.Description = v
						}
					case "always_load":
						info.AlwaysLoad = (v == "true")
					}
				}
			}
		}
	}
	if info.Name == "" {
		info.Name = fallbackName
	}
	if info.Description == "" {
		info.Description = fmt.Sprintf("Skill %s", info.Name)
	}
	return info, nil
}

func bundledSkills() ([]bundledSkill, error) {
	sk, err := parseSkillContent(bundledFilesRWSkill, skillNameFilesRW)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bundled %s skill: %w", skillNameFilesRW, err)
	}
	return []bundledSkill{
		{ShortName: skillNameFilesRW, Skill: sk},
	}, nil
}

func getSkillContent(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case skillNameFilesRW:
		return bundledFilesRWSkill, nil
	default:
		return "", fmt.Errorf("unknown skill %q. Available skills: %s", name, skillNameFilesRW)
	}
}

var skillCmd = &cobra.Command{
	Use:   "skill [files-rw]",
	Short: "List bundled files-rw skills, or print one - if you're an agent, you'll want to load this",
	Long: `With no argument, lists the bundled files-rw skills (name and description) and exits.
With a name (files-rw), prints that skill's full guidance (skills/files-rw/SKILL.md) directly to stdout.

If you're an agent operating in a gated workspace, "files-rw skill" is a reasonable first move.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			skills, err := bundledSkills()
			if err != nil {
				return err
			}
			fmt.Println("Available skills:")
			for _, sk := range skills {
				fmt.Printf("  %-8s  %s\n", sk.ShortName, sk.Skill.Description)
			}
			fmt.Println(`Run "files-rw skill <name>" to print one.`)
			return nil
		}
		content, err := getSkillContent(args[0])
		if err != nil {
			return err
		}
		fmt.Print(content)
		return nil
	},
}

func init() {
	readCmd.Flags().IntVarP(&readStart, "start", "s", 0, "1-indexed starting line number")
	readCmd.Flags().IntVarP(&readEnd, "end", "e", 0, "1-indexed ending line number")
	readCmd.Flags().BoolVarP(&readNumbers, "numbers", "n", false, "format output with cat -n style line numbers (useful before construct edit/patch)")

	tailCmd.Flags().IntVarP(&tailLines, "lines", "n", 10, "number of trailing lines to show")
	tailCmd.Flags().BoolVarP(&tailNumbers, "numbers", "N", false, "format output with cat -n style line numbers")

	editCmd.Flags().StringVar(&editOld, "old", "", "exact string to replace (required)")
	editCmd.Flags().StringVar(&editNew, "new", "", "replacement string")
	editCmd.Flags().BoolVar(&editReplaceAll, "replace-all", false, "replace all occurrences instead of requiring uniqueness")

	listCmd.Flags().BoolVarP(&listLong, "long", "l", false, "use long listing format")
	listCmd.Flags().BoolVarP(&listAll, "all", "a", false, "do not ignore entries starting with .")
	listCmd.Flags().BoolVarP(&listRecursive, "recursive", "R", false, "list subdirectories recursively")
	listCmd.Flags().BoolVar(&listJSON, "json", false, "output in JSON format")

	symlinkCmd.Flags().BoolVarP(&symlinkForce, "force", "f", false, "overwrite an existing link")

	writeCmd.Flags().BoolVar(&writeAllowEmpty, "allow-empty", false, "Allow writing empty (zero-byte) content from stdin")

	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(catCmd)
	rootCmd.AddCommand(writeCmd)
	rootCmd.AddCommand(copyCmd)
	rootCmd.AddCommand(moveCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(editCmd)
	rootCmd.AddCommand(patchCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(symlinkCmd)
	rootCmd.AddCommand(tailCmd)
	rootCmd.AddCommand(appendCmd)
	rootCmd.AddCommand(accessCmd)
	rootCmd.AddCommand(skillCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
