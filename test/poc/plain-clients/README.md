# P0 Plain real-client proof

This proof builds small installable RPM and DEB packages, builds the current
checkout's real `cmd/sow` binary, invokes the public `sow create --json` API,
and consumes the resulting RPM-only,
DEB-only, and mixed flat repositories with real Linux package clients.

Run from the repository root:

```bash
test/poc/plain-clients/run.sh
```

The script uses only locally cached Docker images (`--pull never`) and creates
an isolated directory matching
`/Users/vonng/repo/sow-v2-plain-clients.*`. It refuses any other `LAB_ROOT` and
never reads or writes `/Users/vonng/pgsty/repo`. The lab directory and complete
run log are retained for review. Remove them manually only after confirming the
path is inside the dedicated test prefix.

The proof covers:

- native `x86_64` and neutral `noarch` RPM packages;
- native `amd64` and neutral `all` DEB packages;
- RPM `location href` values equal to package basenames;
- DEB `Filename` values equal to `./<basename>`;
- DNF and YUM metadata refresh, package location, download-only, and install;
- APT update, package location, download-only, and install;
- both protocol sides of a mixed flat directory.
- the stable `sow.cli/v1` JSON envelope and result counts emitted by the actual
  current-checkout binary.

This is local source and client compatibility evidence, not signing, upload,
deployment, or publication evidence.
