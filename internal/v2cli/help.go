package v2cli

import (
	"runtime"
	"strings"
)

// Version is a link-time replaceable binary version.
var Version = "0.2.0"

func VersionString() string {
	return "sow " + Version + " " + runtime.GOOS + "/" + runtime.GOARCH + " " + runtime.Version()
}

// RootHelp returns the complete and deliberately closed P0-P3 command surface.
func RootHelp() string {
	return helpText[""]
}

// Help resolves an Invocation produced by Parse. An empty result means the
// requested help topic is outside the active command tree.
func Help(inv Invocation) string {
	if inv.Command == "help" {
		text, _ := HelpTopic(inv.Positionals...)
		return text
	}
	parts := make([]string, 0, 2)
	if inv.Command != "" {
		parts = append(parts, inv.Command)
	}
	if inv.Subcommand != "" {
		parts = append(parts, inv.Subcommand)
	}
	text, _ := HelpTopic(parts...)
	return text
}

// HelpTopic returns help for the root, a command group, or a leaf command.
func HelpTopic(parts ...string) (string, bool) {
	if len(parts) > 2 {
		return "", false
	}
	key := strings.Join(parts, " ")
	text, ok := helpText[key]
	return text, ok
}

var helpText = map[string]string{
	"": `SOW local package repository manager

Usage:
  sow [OPTIONS] COMMAND [ARGS]

Options:
  -h, --help                         Show help
      --version                      Show version

Commands:
  create [DIR]                       Generate a flat RPM/DEB repository
  init [DIR]                         Initialize a workspace
  config check                       Validate workspace configuration
  config show [--all]                Show workspace configuration
  repo ls                            List repositories
  repo new NAME                      Create a repository
  repo show [NAME]                   Show a repository
  repo migrate [NAME] [--abort]      Migrate or abandon a pre-commit transition
  repo rm NAME [-f|--force]          Remove a repository
  dist ls                            List distributions
  dist new NAME --format rpm|deb     Create a distribution
  dist show NAME                     Show a distribution
  dist rm NAME [-f|--force]          Remove a distribution
  add PATH...                        Add packages to Desired Membership
  rm PACKAGE...                      Remove Desired Membership
  ls                                 List Desired packages
  show PACKAGE                       Show one package object
  where PACKAGE                      Locate a package across repositories
  status                             Show cheap repository state
  build                              Converge Desired to a Built Generation
  check                              Verify repository integrity end to end
  changes [BASE_GENERATION]          Show physical delivery changes
  publish TARGET [--abort]           Publish or abandon a pre-commit attempt
  retain add GENERATION              Retain one verified Generation
  retain ls                          List retained Generations
  retain rm GENERATION               Remove one retained Generation
  gc [TARGET]                        Collect local payloads or maintain one target
  export rpm-leaf DIST ARCH DIR      Export a standalone RPM compatibility leaf
  log [OPERATION]                    Show operation audit records
  log export [FILE]                  Export operation audit as JSONL
  log prune BEFORE                   Prune eligible terminal audit records
  help [COMMAND [SUBCOMMAND]]        Show help
  version                            Show version

Use "sow help COMMAND" for command help.
`,
	"create": `Usage:
  sow create [DIR] [-j N] [--pigsty] [-S KEY [--overwrite]] [-T DUR | -N] [--json]

Options:
  -j, --jobs N          Parallel workers; defaults to logical CPU count
      --pigsty          Enable the atomic Pigsty compatibility operation
  -S, --sign-with KEY   Sign unsigned RPMs with a 16/40/64-hex GPG key ID
      --overwrite       Re-sign every RPM; requires --sign-with
  -T, --timeout DUR     Maximum lock wait; 0 waits indefinitely
  -N, --no-wait         Fail immediately when the lock is held
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"export": `Usage:
  sow export COMMAND

Commands:
  rpm-leaf DIST ARCH DIR [--hardlink]  Export a standalone RPM compatibility leaf

Use "sow help export rpm-leaf" for command help.
`,
	"export rpm-leaf": `Usage:
  sow export rpm-leaf DIST ARCH DIR [--hardlink] [-C DIR] [-r NAME] [--json]

Arguments:
  DIST                 Built RPM distribution name
  ARCH                 Canonical architecture: x86_64 or aarch64
  DIR                  Absent or empty external export root

Options:
      --hardlink       Explicit same-filesystem trusted read-only optimization
  -C, --workdir DIR    Workspace discovery start directory
  -r, --repo NAME      Select a repository
      --json           Emit the versioned JSON envelope
  -h, --help           Show help
`,
	"init": `Usage:
  sow init [DIR] [--json]

Options:
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"config": `Usage:
  sow config COMMAND

Commands:
  check                 Validate workspace configuration
  show [--all]          Show workspace configuration

Use "sow help config COMMAND" for command help.
`,
	"config check": `Usage:
  sow config check [-C DIR] [--json]

Options:
  -C, --workdir DIR     Workspace discovery start directory
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"config show": `Usage:
  sow config show [--all] [-C DIR] [-r NAME] [-d NAME]... [--json]

Options:
      --all             Expand defaults and normalized architectures
  -C, --workdir DIR     Workspace discovery start directory
  -r, --repo NAME       Select a repository
  -d, --dist NAME       Select a distribution; repeatable
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"repo": `Usage:
  sow repo COMMAND

Commands:
  ls                    List repositories
  new NAME              Create a repository
  show [NAME]           Show a repository
  migrate [NAME] [--abort]  Migrate or abandon a pre-commit transition
  rm NAME [-f|--force]  Remove a repository

Use "sow help repo COMMAND" for command help.
`,
	"repo ls": `Usage:
  sow repo ls [-C DIR] [--json]

Options:
  -C, --workdir DIR     Workspace discovery start directory
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"repo new": `Usage:
  sow repo new NAME [-C DIR] [-T DUR | -N] [--json]

Options:
  -C, --workdir DIR     Workspace discovery start directory
  -T, --timeout DUR     Maximum lock wait; 0 waits indefinitely
  -N, --no-wait         Fail immediately when the lock is held
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"repo show": `Usage:
  sow repo show [NAME] [-C DIR] [-r NAME] [--json]

Options:
  -C, --workdir DIR     Workspace discovery start directory
  -r, --repo NAME       Select the repository when NAME is omitted
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"repo migrate": `Usage:
  sow repo migrate [NAME] [--abort] [-j N] [-C DIR] [-r NAME] [-T DUR | -N] [--json]

Options:
  -j, --jobs N          Parallel workers; defaults to logical CPU count
      --abort           Abandon a pre-commit layout migration
  -C, --workdir DIR     Workspace discovery start directory
  -r, --repo NAME       Select the repository when NAME is omitted
  -T, --timeout DUR     Maximum lock wait; 0 waits indefinitely
  -N, --no-wait         Fail immediately when the lock is held
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"repo rm": `Usage:
  sow repo rm NAME [-f|--force] [-C DIR] [-T DUR | -N] [--json]

Options:
  -f, --force           Remove a non-empty unprotected repository
  -C, --workdir DIR     Workspace discovery start directory
  -T, --timeout DUR     Maximum lock wait; 0 waits indefinitely
  -N, --no-wait         Fail immediately when the lock is held
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"dist": `Usage:
  sow dist COMMAND

Commands:
  ls                            List distributions
  new NAME --format rpm|deb     Create a distribution
  show NAME                     Show a distribution
  rm NAME [-f|--force]          Remove a distribution

Use "sow help dist COMMAND" for command help.
`,
	"dist ls": `Usage:
  sow dist ls [-C DIR] [-r NAME] [--json]

Options:
  -C, --workdir DIR     Workspace discovery start directory
  -r, --repo NAME       Select a repository
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"dist new": `Usage:
  sow dist new NAME --format rpm|deb [-C DIR] [-r NAME] [-T DUR | -N] [--json]

Options:
      --format FORMAT   Required; rpm or deb
  -C, --workdir DIR     Workspace discovery start directory
  -r, --repo NAME       Select a repository
  -T, --timeout DUR     Maximum lock wait; 0 waits indefinitely
  -N, --no-wait         Fail immediately when the lock is held
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"dist show": `Usage:
  sow dist show NAME [-C DIR] [-r NAME] [--json]

Options:
  -C, --workdir DIR     Workspace discovery start directory
  -r, --repo NAME       Select a repository
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"dist rm": `Usage:
  sow dist rm NAME [-f|--force] [-C DIR] [-r NAME] [-T DUR | -N] [--json]

Options:
  -f, --force           Remove membership and indexes but retain pool packages
  -C, --workdir DIR     Workspace discovery start directory
  -r, --repo NAME       Select a repository
  -T, --timeout DUR     Maximum lock wait; 0 waits indefinitely
  -N, --no-wait         Fail immediately when the lock is held
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"add": `Usage:
  sow add PATH... [-R|--recursive] [--skip] [-j|--jobs N] [-C|--workdir DIR] [-r|--repo NAME] [-d|--dist NAME]... [-T|--timeout DUR | -N|--no-wait] [--json]
`,
	"rm": `Usage:
  sow rm PACKAGE... [-c|--check] [--skip] [-j|--jobs N] [-C|--workdir DIR] [-r|--repo NAME] [-d|--dist NAME]... [-T|--timeout DUR | -N|--no-wait] [--json]
`,
	"ls": `Usage:
  sow ls [-C|--workdir DIR] [-r|--repo NAME] [-d|--dist NAME]... [--json]
`,
	"show": `Usage:
  sow show PACKAGE [-C|--workdir DIR] [-r|--repo NAME] [-d|--dist NAME]... [--json]
`,
	"where": `Usage:
  sow where PACKAGE [-C|--workdir DIR] [-r|--repo NAME] [-d|--dist NAME]... [--json]
`,
	"status": `Usage:
  sow status [-C|--workdir DIR] [-r|--repo NAME] [-d|--dist NAME]... [--json]
`,
	"build": `Usage:
  sow build [-j|--jobs N] [-C|--workdir DIR] [-r|--repo NAME] [-d|--dist NAME]... [-T|--timeout DUR | -N|--no-wait] [--json]
`,
	"check": `Usage:
  sow check [-j|--jobs N] [-C|--workdir DIR] [-r|--repo NAME] [-d|--dist NAME]... [--json]
`,
	"changes": `Usage:
  sow changes [BASE_GENERATION] [-C|--workdir DIR] [-r|--repo NAME] [--json]
`,
	"publish": `Usage:
  sow publish TARGET [--abort] [-C|--workdir DIR] [-T|--timeout DUR | -N|--no-wait] [--json]

Arguments:
  TARGET                Configured filesystem or R2 target name

Options:
      --abort           Abandon a reconciled pre-commit attempt
  -C, --workdir DIR     Workspace discovery start directory
  -T, --timeout DUR     Maximum lock wait; 0 waits indefinitely
  -N, --no-wait         Fail immediately when the lock is held
      --json            Emit the versioned JSON envelope
  -h, --help            Show help
`,
	"retain": `Usage:
  sow retain COMMAND

Commands:
  add GENERATION        Retain the current verified Generation
  ls                    List retained Generations
  rm GENERATION         Remove one retained Generation

Use "sow help retain COMMAND" for command help.
`,
	"retain add": `Usage:
  sow retain add GENERATION [-C|--workdir DIR] [-r|--repo NAME] [-T|--timeout DUR | -N|--no-wait] [--json]
`,
	"retain ls": `Usage:
  sow retain ls [-C|--workdir DIR] [-r|--repo NAME] [--json]
`,
	"retain rm": `Usage:
  sow retain rm GENERATION [-C|--workdir DIR] [-r|--repo NAME] [-T|--timeout DUR | -N|--no-wait] [--json]
`,
	"gc": `Usage:
  sow gc [TARGET] [-C|--workdir DIR] [-r|--repo NAME] [-T|--timeout DUR | -N|--no-wait] [--json]

Arguments:
  TARGET                Optional publication target; omitting it runs local GC

Target behavior:
  Filesystem targets conditionally delete only after grace and absence receipts.
  R2 targets persist exact retained-candidate reports and never delete objects.
`,
	"log": `Usage:
  sow log [OPERATION] [-C|--workdir DIR] [-r|--repo NAME] [-d|--dist NAME] [--json]
  sow log export [FILE] [-C|--workdir DIR] [-r|--repo NAME] [-d|--dist NAME]
  sow log prune BEFORE [-C|--workdir DIR] [-r|--repo NAME] [-T|--timeout DUR | -N|--no-wait] [--json]
`,
	"log export": `Usage:
  sow log export [FILE] [-C|--workdir DIR] [-r|--repo NAME] [-d|--dist NAME]
`,
	"log prune": `Usage:
  sow log prune BEFORE [-C|--workdir DIR] [-r|--repo NAME] [-T|--timeout DUR | -N|--no-wait] [--json]
`,
	"help": `Usage:
  sow help [COMMAND [SUBCOMMAND]]
`,
	"version": `Usage:
  sow version
`,
}
