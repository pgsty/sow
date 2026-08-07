# repo2 ordinary repository acceptance

> **Historical v0.2 C2 harness.** 本 fixture 的 view-local package aliases 与 reposync
> PASS 仍证明 `v0.2.0`，但下一版明确不生成这些 aliases；前向门禁见
> [`design/next`](../../../design/next/)。

This retained-lab proof uses `/Users/vonng/pgsty/repo2` strictly as read-only
input. It compares current-checkout SOW Plain metadata with `createrepo_c` and
`dpkg-scanpackages`, then builds a signed Managed repository from native and
neutral repo2 packages. Real amd64 and arm64 DNF/APT clients consume the
repository over both `file://` and HTTP; DNF also runs `reposync` against the
C2 views. The proof finishes by applying `changes 0` in phase order, pruning
eligible audit log rows, and checking that the repository remains clean.

Run from the repository root:

```bash
test/poc/repo2-ordinary-acceptance/run.sh
```

The script creates and retains an isolated directory matching
`/Users/vonng/repo/sow-v2-repo2-ordinary.*`. It refuses every other output
prefix and never mounts repo2 writable. Signing uses a disposable, unencrypted
test key created inside the lab; it never reads a production private key and
does not publish anything.
