# Edge Case Hunter review prompt: complete CLI help flags

Invoke the `bmad-review-edge-case-hunter` skill on the exact focused diff and
intent in
`_bmad-output/implementation-artifacts/review-prompt-cli-help-blind-hunter.md`.
Work without prior conversation context. The shared worktree contains unrelated
changes; do not review or edit them.

Walk every relevant help boundary, including at minimum:

- no arguments, top-level `help`, unknown command, `-h`, and `--help`;
- flags supplied before and after `--help`, including repeatable/custom flags;
- bool, scalar, empty-default, non-empty-default, and custom `flag.Value`
  rendering through `FlagSet.PrintDefaults`;
- exact registered flag-name matching (prefix collisions must not create a
  false positive);
- every implemented command: `init`, `add`, `rm`, `sync`, `promote`, `publish`,
  `verify`, `fsck`, `materialize`, and `gc`;
- common `config/root/repo/os/arch/workers/chunk-entries/recover` flags where
  registered, command-specific GPG/secret flags, `max-findings`, and
  `restore-generation`;
- preservation of publish restore/stable explanatory notes;
- stdout/stderr and ExitOK/ExitUsage semantics;
- accidental echo of caller-provided secret paths/values or disclosure through
  defaults and error paths;
- future flags added after the Usage callback is assigned but before parsing;
- help formatting stability, empty notes, and commands with positional
  arguments.

Return only unhandled edge cases, each with file, line, reproducible path, and
user consequence. Do not restate covered cases.
