# Blind Hunter Review Prompt: Route-safe URL Paths

Invoke the `bmad-review-adversarial-general` skill on the following scoped change in `/Users/vonng/pgsty/sow`.

Read `_bmad-output/implementation-artifacts/spec-route-safe-url-paths.md` first. The worktree was already dirty before this story, so review only these changes and their direct interactions:

- `internal/config/config.go`: `validateRepos` now routes repo arches, APT suites/components, YUM OS selector values, and expanded repository paths through `validateRouteStringList` / `validateRoutePath`; new exported `ValidateRouteSegment` implements ASCII `[A-Za-z0-9+._~^:-]` plus empty/dot-segment rejection.
- `internal/config/config_test.go`: new route vocabulary, invalid configuration wiring, and valid expanded-path tests.
- `internal/cli/add.go`: `addAssetFiles` validates every logical destination and replace policy before creating/importing into CAS; `assetLogicalPath` validates each segment with `config.ValidateRouteSegment`.
- `internal/cli/add_test.go`: new logical path matrix and end-to-end proof that an invalid destination creates no CAS object/ref/materialization while a legal boundary-character path succeeds.

The prior behavior rejected only absolute/backslash/control/escape paths in config; asset destinations rejected `%?#`, backslash/control/escape/reserved segments, and CAS import happened before destination validation. The frozen JavaScript contract is `edge/shared/contract.mjs`: `SAFE_SEGMENT = /^[A-Za-z0-9+._~^:-]+$/`, with explicit `.` / `..` rejection and all percent-encoded paths rejected.

Do not modify files. Report only reproducible bugs, regressions, or unmet acceptance criteria with `file:line`, triggering input, consequence, and recommended correction. State `none` if no real finding remains.
