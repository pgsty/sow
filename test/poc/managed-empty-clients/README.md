# Managed empty Dist real-client acceptance

This harness builds the current checkout's public `sow` binary, creates one
Managed Repository with an empty RPM Dist and an empty DEB Dist, and consumes
every generated architecture index with real Linux package clients.

It verifies:

- `sow init`, `repo new`, `dist new`, `config check`, and `dist ls` through the
  public JSON CLI;
- empty RPM views for `x86_64` and `aarch64` over both `file://` and HTTP
  with DNF/YUM refresh, query, and reposync;
- empty DEB indexes for `amd64` and `arm64` over both `file:` and HTTP with
  APT refresh and query;
- unsigned defaults (no accidental signature placeholders);
- a lab-only mutation boundary under
  `/Users/vonng/repo/sow-v2-managed-empty.*`.

Run from any directory:

```bash
test/poc/managed-empty-clients/run.sh
```

The script retains its lab directory and full log for review. It never reads
or writes `/Users/vonng/pgsty/repo`, and it performs no signing, upload,
publication, or remote repository mutation.

The final fresh run on 2026-08-02 exited 0. Its retained lab is
`/Users/vonng/repo/sow-v2-managed-empty.w4TX1D`, and the complete `run.log`
SHA-256 is
`f442597d3c962e2a6b22d8c09322b88181febd8d70cd9caa38221d734584b607`.
It is bound to product source fingerprint
`5b9d1b404ea535701ad61648efd55cb713089816e7d1465c9c44655c1cba3aba`.
The labelled container, network, and volumes were absent after cleanup. See
[`evidence/2026-08-01.md`](evidence/2026-08-01.md) for the earlier file-client
run and historical client details; it is not the final HTTP-capable result.
