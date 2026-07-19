# Edge Case Hunter Review Prompt: Route-safe URL Paths

Invoke the `bmad-review-edge-case-hunter` skill on the following scoped change in `/Users/vonng/pgsty/sow`.

Read `_bmad-output/implementation-artifacts/spec-route-safe-url-paths.md` first. Ignore unrelated pre-existing dirty-worktree changes and exhaustively walk boundaries in:

- `internal/config/config.go`: route-safe segment/path validators and their wiring into expanded repo paths, APT suite/component, repo arch, and YUM OS route values.
- `internal/config/config_test.go`: the three new route-safe tests.
- `internal/cli/add.go`: all logical asset paths are validated before CAS import; each destination segment reuses `config.ValidateRouteSegment`.
- `internal/cli/add_test.go`: the two new asset route-safe tests.

Compare Go behavior against `edge/shared/contract.mjs`, whose effective clean-route contract is: non-empty ASCII segments matching `[A-Za-z0-9+._~^:-]`, no `.` or `..`, no `%` encoding, query, fragment, backslash, duplicate separators, or control characters. Check raw vs expanded YUM `{arch}` paths, asset default basenames and explicit `--dest`, multi-input atomic prevalidation, dot/empty segments, non-ASCII bytes, every allowed punctuation boundary, error classification, and whether rejected input can leave CAS/ref/materialization state.

Do not modify files. Report only unhandled edge cases with `file:line`, exact triggering input, consequence, and smallest correction. State `none` if exhaustive review finds no gap.
