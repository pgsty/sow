#!/usr/bin/env python3
"""Guard actual os.File bytes for the existing 1 MiB DEB Check fixture only.

Go upgrades must review all four instrumented methods and rerun green/red on CI's
OS before updating the version/hash/anchors. Budgets are evidence, not calibration.
This measures returned bytes, not disk traffic, mmap, or direct syscall reads.
Only Python's standard library is required; modules must already be available.
"""

import atexit
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

TEST = "TestCheckMissingFactsUsesAuthenticatedKnownHeaderWithoutSecondPayloadRead"
SIZE = 1050816
MARKER = "SOW_CHECK_OS_IO "
OS_HASH = "d77653afbcbec5256b56aee25dce3df3ed001f964c9b245b848a5d378884bcb3"
CHECK = '''\tcheckOnce := func(name string, wantFactRows int64) {
\t\tt.Helper()
\t\tcheckCtx, collector := workmetrics.Ensure(context.Background())
\t\tif checked, err := Check(checkCtx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 2}); err != nil || !checked.ReadyToCopy {
\t\t\tt.Fatalf("%s check=%#v err=%v", name, checked, err)
\t\t}
\t\tmetrics := collector.Snapshot()
\t\tif metrics.FullPackageReads != 1 || metrics.PayloadBytesRead != int64(len(body)) || metrics.SignatureStreams != 0 || metrics.FactRowsRead != wantFactRows || metrics.PayloadByPhase["check_authenticity"].Full != 1 {
\t\t\tt.Fatalf("%s check metrics=%#v", name, metrics)
\t\t}
\t\tt.Logf("%s: 3 Dists, 2 architectures, 3 retained Generations, %d full read, %d bytes, phases=%v", name, metrics.FullPackageReads, metrics.PayloadBytesRead, metrics.PayloadByPhase)
\t}'''
OBSERVER = '''package os
import "sync/atomic"
var sowCheckIOObserver atomic.Pointer[func(*File, string, int64)]
func SOWCheckSetIOObserver(f func(*File, string, int64)) bool {
    if f == nil { return sowCheckIOObserver.Swap(nil) != nil }
    return sowCheckIOObserver.CompareAndSwap(nil, &f)
}
func SOWCheckIOActive() bool { return sowCheckIOObserver.Load() != nil }
func sowCheckObserveIO(f *File, kind string, n int64) {
    if cb := sowCheckIOObserver.Load(); cb != nil && (n > 0 || kind == "ReadFrom" || kind == "WriteTo") {
        (*cb)(f, kind, n)
    }
}
'''
# Fault injection of the old unrecorded full-hash mechanism, not the old commit.
EXTRA_HASH = '''\tif os.SOWCheckIOActive() {
\t\tif _, err := reader.Seek(0, io.SeekStart); err != nil {
\t\t\treturn "", "", err
\t\t}
\t\tif _, err := io.Copy(sha256.New(), &managedContextReader{ctx: ctx, reader: reader}); err != nil {
\t\t\treturn "", "", err
\t\t}
\t}
'''


def replace_once(source, anchor, replacement):
    if source.count(anchor) != 1:
        raise RuntimeError("source anchor changed; review the Check I/O guard before updating it")
    return source.replace(anchor, replacement, 1)


def run_case(go, root, scratch, env, overlay, negative):
    name = "red" if negative else "green"
    command = go + ["test", "-json", "-count=1", "-mod=readonly", "-timeout=120s",
                    "-overlay=" + str(overlay), "-run=^" + TEST + "$", "./internal/v2/managed"]
    started = time.monotonic()
    result = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True, timeout=600)
    elapsed = round(time.monotonic() - started, 3)
    (scratch / (name + ".jsonl")).write_text(result.stdout)
    (scratch / (name + ".stderr.log")).write_text(result.stderr)
    (scratch / (name + "-run.json")).write_text(json.dumps({
        "command": command, "seconds": elapsed, "exit_code": result.returncode}, indent=2) + "\n")
    events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    actions = [e["Action"] for e in events if e.get("Test") == TEST and e["Action"] in ("pass", "fail", "skip")]
    package_actions = [e["Action"] for e in events if not e.get("Test") and e["Action"] in ("pass", "fail", "skip")]
    outcome = "fail" if negative else "pass"
    if (result.returncode != int(negative) or result.stderr or actions != [outcome] or
            package_actions != [outcome] or any(e["Action"] == "skip" or e.get("FailedBuild") for e in events) or
            [e.get("Test") for e in events if e["Action"] == "run"] != [TEST]):
        raise RuntimeError(name + " did not execute exactly the expected test/outcome; see logs")
    output = [e.get("Output", "") for e in events if e.get("Test") == TEST and e["Action"] == "output"]
    records = [json.loads(line.split(MARKER, 1)[1]) for line in output if MARKER in line]
    expected = [{"window": "cached facts", "read": SIZE * (2 if negative else 1),
                 "read_at": 0, "logical_full": 1, "logical_bytes": SIZE, "problem": ""}]
    if not negative:
        expected.append(dict(expected[0], window="missing facts", read_at=2428))
    if records != expected:
        raise RuntimeError(name + " missing or unexpected exact byte-window records: " + repr(records))
    if negative:
        package_output = [e.get("Output", "") for e in events if not e.get("Test") and e["Action"] == "output"]
        if (len(package_output) != 2 or package_output[0] != "FAIL\n" or
                not re.fullmatch(r"FAIL\tgithub\.com/pgsty/sow/internal/v2/managed\t[0-9.]+s\n", package_output[1])):
            raise RuntimeError("red produced unexpected package output instead of the sole budget failure")
        # A generic failing process is not a red control. Allow only the one
        # budget failure, with no additional assertion, panic, or cleanup error.
        budget = r"    check_test\.go:\d+: SOW_CHECK_OS_IO_BUDGET cached facts\n"
        if (len(output) != 4 or output[0] != "=== RUN   " + TEST + "\n" or
                MARKER not in output[1] or not re.fullmatch(budget, output[2]) or
                not re.fullmatch(r"--- FAIL: " + TEST + r" \([0-9.]+s\)\n", output[3])):
            raise RuntimeError("red failed for something other than the sole byte budget assertion")
    print(json.dumps({"case": name, "seconds": elapsed, "records": records, "accepted": True}), flush=True)


def main():
    root = Path(__file__).resolve().parents[2]
    # Ignore TMPDIR: keep fixture paths short and all generated sources/logs out
    # of the checkout. Retain this directory for diagnosing either outcome.
    temp_root = Path("/tmp").resolve()
    if temp_root.is_relative_to(root):
        raise RuntimeError("temporary output would be inside the checkout")
    scratch = Path(tempfile.mkdtemp(prefix="sowio-", dir=temp_root)).resolve()
    print("Check OS I/O artifacts: " + str(scratch), flush=True)
    # Preserve normal selection and checksum trust during discovery. GOPROXY
    # blocks downloads; Go may still verify cached toolchains with its sumdb.
    env = dict(os.environ, GOWORK="off", GOPROXY="off")
    go = shlex.split(env.get("GO", "go"))
    selection = go + ["env", "-json", "GOVERSION", "GOROOT", "GOMODCACHE", "GOCACHE", "GOOS", "GOARCH", "GOTOOLCHAIN", "GOSUMDB"]
    info = json.loads(subprocess.check_output(selection, cwd=root, env=env, text=True))
    if info["GOVERSION"] != "go1.27.2":
        raise RuntimeError("Check OS I/O guard requires go1.27.2; review methods and budgets on upgrade")
    if any(Path(info[key]).resolve().is_relative_to(root) for key in ("GOCACHE", "GOMODCACHE")):
        raise RuntimeError("Check OS I/O guard requires caches outside the checkout")
    goroot = Path(info["GOROOT"]).resolve()
    go = [str(goroot / "bin/go")]
    env.update(GOTOOLCHAIN="local", GOSUMDB="off")
    version = subprocess.check_output(go + ["version"], cwd=root, env=env, text=True).strip()
    if not version.startswith("go version " + info["GOVERSION"] + " "):
        raise RuntimeError("selected Go binary version differs from toolchain discovery")
    original = (goroot / "src/os/file.go").read_bytes()
    if hashlib.sha256(original).hexdigest() != OS_HASH:
        raise RuntimeError("os/file.go changed; review all four observer insertion paths")
    # Downloaded toolchains live inside GOMODCACHE, where Go rejects overlays.
    # A private read-only alias preserves that cache and the installed GOROOT.
    if goroot.is_relative_to(Path(info["GOMODCACHE"]).resolve()):
        alias = scratch / "goroot"
        alias.symlink_to(goroot, target_is_directory=True)
        atexit.register(alias.unlink, missing_ok=True)
        goroot = alias
        env["GOROOT"] = str(alias)
    (scratch / "tmp").mkdir()
    env["TMPDIR"] = str(scratch / "tmp")
    env["GOTMPDIR"] = env["TMPDIR"]
    (scratch / "toolchain.json").write_text(json.dumps(dict(
        info, selection_command=selection, selected_binary_version=version,
        go_command=go, resolved_go=str(Path(shutil.which(go[0])).resolve()),
        execution_GOTOOLCHAIN=env["GOTOOLCHAIN"], execution_GOSUMDB=env["GOSUMDB"],
        overlay_goroot=str(goroot), temporary_dir=env["TMPDIR"]), indent=2) + "\n")
    source = original.decode()
    for signature, kind in [("Read(b []byte)", "Read"), ("ReadAt(b []byte, off int64)", "ReadAt")]:
        anchor = "func (f *File) " + signature + " (n int, err error) {\n"
        source = replace_once(source, anchor, anchor + '\tdefer func() { sowCheckObserveIO(f, "' + kind + '", int64(n)) }()\n')
    anchor = '\t\treturn genericReadFrom(f, r) // without wrapping\n\t}\n\treturn n, f.wrapErr("write", e)'
    source = replace_once(source, anchor, anchor.replace('\treturn n,', '\tsowCheckObserveIO(f, "ReadFrom", n)\n\treturn n,'))
    anchor = '\tn, handled, e := f.writeTo(w)\n\tif handled {\n'
    source = replace_once(source, anchor, anchor + '\t\tsowCheckObserveIO(f, "WriteTo", n)\n')
    replacements = {}

    def add(virtual, filename, content):
        actual = scratch / filename
        actual.write_text(content)
        replacements[str(virtual)] = str(actual)

    add(goroot / "src/os/file.go", "file.go", source)
    add(goroot / "src/os/sow_check_io.go", "os-observer.go", OBSERVER)
    managed = root / "internal/v2/managed"
    instrumented = CHECK.replace('\t\tif checked,', '\t\tstop := sowCheckObserve(t, root, len(body))\n\t\tdefer stop()\n\t\tif checked,')
    instrumented = instrumented.replace('\t\tmetrics :=', '\t\tactual := stop()\n\t\tmetrics :=')
    instrumented = instrumented.replace('\t\tt.Logf(', '\t\tsowCheckAssert(t, name, actual, metrics)\n\t\tt.Logf(')
    add(managed / "check_test.go", "check_test.go", replace_once((managed / "check_test.go").read_text(), CHECK, instrumented))
    add(managed / "check_os_io_test.go", "check_os_io_test.go", (root / "qa/perf/testdata/check_os_io_test.go").read_text())
    overlay = scratch / "green-overlay.json"
    overlay.write_text(json.dumps({"Replace": replacements}))
    run_case(go, root, scratch, env, overlay, False)
    source = (managed / "check_evidence.go").read_text()
    anchor = '\tneutral := ""\n\tif neutralOffset >= 0 {'
    add(managed / "check_evidence.go", "check_evidence.go", replace_once(source, anchor, EXTRA_HASH + anchor))
    overlay = scratch / "red-overlay.json"
    overlay.write_text(json.dumps({"Replace": replacements}))
    run_case(go, root, scratch, env, overlay, True)
    print("Check OS I/O contract: PASS (green and strict unrecorded-hash red control)")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit("Check OS I/O contract: FAIL: " + str(error))
