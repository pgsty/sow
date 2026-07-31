package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestSnapshotL1AcceptsAbsentEmptyPackagePayloadTrees(t *testing.T) {
	for _, fixture := range []struct {
		name        string
		config      string
		repo        string
		os          string
		arch        string
		repoPath    string
		payloadPath string
	}{
		{
			name: "apt", config: snapshotAPTConfig, repo: "deb-test", os: "jammy", arch: "arm64",
			repoPath: "apt/test", payloadPath: "apt/test/pool",
		},
		{
			name: "yum", config: snapshotYUMConfig, repo: "rpm-test", os: "el10", arch: "x86_64",
			repoPath: "yum/test/x86_64", payloadPath: "yum/test/x86_64/Packages",
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root := nginxWorkerTempDir(t)
			configPath := filepath.Join(root, "sow.yaml")
			if err := os.WriteFile(configPath, []byte(fixture.config), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(fixture.repoPath)), 0o755); err != nil {
				t.Fatal(err)
			}
			_, keyPath := writeMaterializeSigningKey(t, root)
			publicKeyPath := writeVerifyPublicKey(t, keyPath)
			run := func(arguments ...string) (int, string, string) {
				t.Helper()
				var stdout, stderr bytes.Buffer
				code := Main(arguments, &stdout, &stderr)
				return code, stdout.String(), stderr.String()
			}
			if code, stdout, stderr := run("init", "--config", configPath, "--workers", "1", "--chunk-entries", "1"); code != ExitOK {
				t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}

			stageDir := filepath.Join(root, ".sow", "staging", "test-empty-snapshot")
			if err := os.MkdirAll(stageDir, 0o700); err != nil {
				t.Fatal(err)
			}
			empty := filepath.Join(stageDir, "empty-stable.tsv")
			if err := os.WriteFile(empty, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			viewPath, err := state.ViewPath("stable", fixture.repo, fixture.os, fixture.arch)
			if err != nil {
				t.Fatal(err)
			}
			viewRef, err := state.ViewRef("stable", fixture.repo, fixture.os, fixture.arch)
			if err != nil {
				t.Fatal(err)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			if _, changed, err := applyCanonicalState(
				t.Context(), canonical, "test-empty-stable", "test: seed empty stable package view",
				map[string]string{viewPath: empty}, []state.RefUpdate{{Name: viewRef}}, state.ApplyOptions{},
			); err != nil || !changed {
				t.Fatalf("seed empty stable changed=%v err=%v", changed, err)
			}

			snapshotID, err := views.SnapshotID(fixture.os, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if code, stdout, stderr := run("promote", "stable", snapshotID, "--config", configPath, "--repo", fixture.repo); code != ExitOK {
				t.Fatalf("snapshot code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			if code, stdout, stderr := run(
				"materialize", snapshotID, "--config", configPath, "--repo", fixture.repo,
				"--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1",
			); code != ExitOK {
				t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}

			payload := filepath.Join(
				root, ".sow", "materialized", "snapshots", snapshotID,
				filepath.FromSlash(fixture.payloadPath),
			)
			if _, err := os.Lstat(payload); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("empty snapshot payload scope exists at %s: %v", payload, err)
			}
			code, stdout, stderr := run(
				"verify", "--layer", "L1", "--snapshot", snapshotID,
				"--config", configPath, "--repo", fixture.repo,
				"--gpg-public-key-file", publicKeyPath, "--workers", "1", "--chunk-entries", "1",
			)
			if code != ExitOK || !strings.Contains(stdout, "verify outcome=passed") {
				t.Fatalf("empty snapshot L1 code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
		})
	}
}

func TestMaterializeAPTSnapshotBuildsConsumableRepositoryAndRebuildsAfterRetention(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(snapshotAPTConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	debPath := decodeMaterializeFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "package.deb"))
	debInfo, err := aptrepo.InspectPackage(context.Background(), debPath, "main")
	if err != nil {
		t.Fatal(err)
	}
	private, keyPath := writeMaterializeSigningKey(t, root)
	publicKeyPath := writeVerifyPublicKey(t, keyPath)
	run := func(arguments ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", debPath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "deb-test"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotID, err := views.SnapshotID("jammy", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("promote", "stable", snapshotID, "--config", configPath, "--repo", "deb-test"); code != ExitOK {
		t.Fatalf("snapshot code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	originalNow := timeNowUTC
	timeNowUTC = func() time.Time { return time.Now().UTC().AddDate(1, 0, 0) }
	t.Cleanup(func() { timeNowUTC = originalNow })
	archivePath := filepath.Join(root, "offline", "pigsty-pkg-jammy.tgz")
	materialize := []string{"materialize", snapshotID, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--tgz", archivePath, "--workers", "2", "--chunk-entries", "2"}
	code, stdout, stderr := run(materialize...)
	if code != ExitOK || !strings.Contains(stdout, "apt_suites=1") {
		t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	firstArchive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	snapshotRoot := filepath.Join(root, ".sow", "materialized", "snapshots", snapshotID, "apt", "test")
	assertAPTSnapshotRepository(t, snapshotRoot, snapshotID, debInfo.PoolPath, private)
	code, verifyOutput, verifyError := run("verify", "--layer", "L1", "--snapshot", snapshotID, "--config", configPath, "--repo", "deb-test", "--gpg-public-key-file", publicKeyPath, "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(verifyOutput, "outcome=passed") {
		t.Fatalf("snapshot APT L1 code=%d stdout=%s stderr=%s", code, verifyOutput, verifyError)
	}
	assertArchiveNames(t, firstArchive,
		"apt/test/dists/"+snapshotID+"/InRelease",
		"apt/test/dists/"+snapshotID+"/Release.gpg",
		"apt/test/dists/"+snapshotID+"/main/binary-arm64/Packages",
		"apt/test/"+debInfo.PoolPath,
	)

	code, stdout, stderr = run("materialize", "stable", "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(stdout, "pruned_snapshots=1") {
		t.Fatalf("retention code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Dir(snapshotRoot)); !os.IsNotExist(err) {
		t.Fatalf("expired derived snapshot remains after stable retention: %v", err)
	}
	code, stdout, stderr = run(materialize...)
	if code != ExitOK {
		t.Fatalf("on-demand rebuild code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	secondArchive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstArchive, secondArchive) {
		t.Fatal("complete APT snapshot tgz changed after retention and on-demand rebuild")
	}
	assertAPTSnapshotRepository(t, snapshotRoot, snapshotID, debInfo.PoolPath, private)
}

func TestMaterializeYUMSnapshotBuildsSignedIndependentHardlinkTreeAndCompleteTGZ(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(snapshotYUMConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	private, keyPath := writeMaterializeSigningKey(t, root)
	run := func(arguments ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotID, err := views.SnapshotID("el10", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("promote", "stable", snapshotID, "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
		t.Fatalf("snapshot code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	archivePath := filepath.Join(root, "offline", "pigsty-pkg-el10.tgz")
	arguments := []string{"materialize", snapshotID, "--config", configPath, "--repo", "rpm-test", "--target", "export-yum", "--gpg-private-key-file", keyPath, "--tgz", archivePath, "--workers", "2", "--chunk-entries", "2"}
	code, stdout, stderr := run(arguments...)
	if code != ExitOK || !strings.Contains(stdout, "yum_repos=1") {
		t.Fatalf("materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	firstArchive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	repoRoot := filepath.Join(root, "export-yum", "yum", "test", "x86_64")
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(private), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	packageTrust, err := os.ReadFile(filepath.Join(root, "package-trust.asc"))
	if err != nil {
		t.Fatal(err)
	}
	packageKeyring, err := openpgp.ReadKeyRing(bytes.NewReader(packageTrust))
	if err != nil {
		t.Fatal(err)
	}
	report := verify.Run(context.Background(), verify.Request{Layers: []verify.Layer{verify.LayerL1}, Checks: []verify.Check{verify.YUMCheck{
		CheckID: "snapshot-yum", Root: repoRoot, Compression: yumrepo.CompressionZstd, Verifier: verifier,
		PackageKeyring: packageKeyring, VerifyAt: time.Now().UTC(), Workers: 2, ChunkEntries: 2,
	}}})
	if report.Outcome != verify.OutcomePassed {
		t.Fatalf("materialized YUM snapshot is not consumable: %+v", report)
	}
	info, err := yumrepo.InspectPackage(context.Background(), yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	packageInfo, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(info.Location)))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := repository.ParseDigest(info.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	poolInfo, err := os.Stat(filepath.Join(root, ".pool", "sha256", info.SHA256[:2], digest.String()))
	if err != nil || !os.SameFile(packageInfo, poolInfo) {
		t.Fatalf("YUM snapshot payload is not a CAS hardlink: %v", err)
	}
	assertArchiveNames(t, firstArchive,
		"yum/test/x86_64/repodata/repomd.xml",
		"yum/test/x86_64/repodata/repomd.xml.asc",
		"yum/test/x86_64/"+info.Location,
	)
	code, stdout, stderr = run(arguments...)
	if code != ExitOK {
		t.Fatalf("replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	secondArchive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstArchive, secondArchive) {
		t.Fatalf("complete YUM snapshot tgz is not deterministic: %s", archiveDifference(t, firstArchive, secondArchive))
	}
}

func TestSnapshotRetentionUsesNaturalMonthsAndFailsClosedOnUnsafeTree(t *testing.T) {
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	for id, want := range map[string]bool{
		"jammy-20260201": true,
		"jammy-20260131": false,
		"jammy-20260712": true,
	} {
		got, err := retainMaterializedSnapshot(id, now, 6)
		if err != nil || got != want {
			t.Fatalf("retain %s = %v, %v; want %v", id, got, err, want)
		}
	}
	if _, err := retainMaterializedSnapshot("jammy-20260713", now, 6); err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("future snapshot was not rejected: %v", err)
	}
	root := t.TempDir()
	unsafe := filepath.Join(root, ".sow", "materialized", "snapshots", "jammy-20200101")
	if err := os.MkdirAll(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(unsafe, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := pruneExpiredSnapshotMaterializations(root, "", 1, now); err == nil || !strings.Contains(err.Error(), "unsafe derived snapshot") {
		t.Fatalf("unsafe retention tree was not rejected: %v", err)
	}
	if _, err := os.Lstat(unsafe); err != nil {
		t.Fatalf("unsafe tree was modified: %v", err)
	}
}

func assertAPTSnapshotRepository(t *testing.T, root, suite, poolPath string, private []byte) {
	t.Helper()
	verifier, err := verify.NewAPTVerifier(bytes.NewReader(private))
	if err != nil {
		t.Fatal(err)
	}
	report := verify.Run(context.Background(), verify.Request{Layers: []verify.Layer{verify.LayerL1}, Checks: []verify.Check{verify.APTCheck{
		CheckID: "snapshot-apt", Root: root, ExpectedSuites: []string{suite}, Verifier: verifier,
		VerifyAt: time.Now().UTC().AddDate(1, 0, 0), Workers: 2, ChunkEntries: 2,
	}}})
	if report.Outcome != verify.OutcomePassed {
		t.Fatalf("materialized APT snapshot is not consumable: %+v", report)
	}
	release, err := os.ReadFile(filepath.Join(root, "dists", suite, "Release"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(release), "Suite: "+suite+"\n") || !strings.Contains(string(release), "Codename: "+suite+"\n") || !strings.Contains(string(release), "Acquire-By-Hash: yes\n") {
		t.Fatalf("snapshot Release identity is incomplete:\n%s", release)
	}
	if _, err := aptrepo.InspectPackage(context.Background(), filepath.Join(root, filepath.FromSlash(poolPath)), "main"); err != nil {
		t.Fatal(err)
	}
}

func writeMaterializeSigningKey(t *testing.T, root string) ([]byte, string) {
	t.Helper()
	created := time.Now().UTC().Add(-24 * time.Hour)
	entity, err := openpgp.NewEntity("SOW materialize", "", "materialize@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	if err := entity.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	var public bytes.Buffer
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "signing.key")
	if err := os.WriteFile(path, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "repository-public.pgp"), public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	writeRPMPackageTrustFixture(t, root)
	return append([]byte(nil), private.Bytes()...), path
}

func writeRPMPackageTrustFixture(t *testing.T, root string) string {
	t.Helper()
	keyFiles := []string{
		filepath.Join("..", "..", "test", "compat", "testdata", "PGDG-RPM-GPG-KEY-RHEL-nonfree.asc"),
		filepath.Join("..", "..", "third_party", "cavaliergopher-rpm", "testdata", "RPM-GPG-KEY-CentOS-4"),
		filepath.Join("..", "..", "third_party", "cavaliergopher-rpm", "testdata", "RPM-GPG-KEY-CentOS-5"),
	}
	var bundle bytes.Buffer
	for _, keyFile := range keyFiles {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatal(err)
		}
		entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
		if err != nil || len(entities) == 0 {
			t.Fatalf("parse package trust key %s: entities=%d err=%v", keyFile, len(entities), err)
		}
		for _, entity := range entities {
			if err := entity.Serialize(&bundle); err != nil {
				t.Fatal(err)
			}
		}
	}
	filename := filepath.Join(root, "package-trust.asc")
	if err := os.WriteFile(filename, bundle.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return filename
}

func decodeMaterializeFixture(t *testing.T, source, destination string) string {
	t.Helper()
	encoded, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, payload, 0o444); err != nil {
		t.Fatal(err)
	}
	return destination
}

func assertArchiveNames(t *testing.T, encoded []byte, names ...string) {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	found := make(map[string]bool)
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		found[header.Name] = true
	}
	for _, name := range names {
		if !found[name] {
			t.Fatalf("complete offline archive omitted %s; entries=%v", name, found)
		}
	}
}

func assertArchiveOmitsNames(t *testing.T, encoded []byte, names ...string) {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	forbidden := make(map[string]struct{}, len(names))
	for _, name := range names {
		forbidden[name] = struct{}{}
	}
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, denied := forbidden[header.Name]; denied {
			t.Fatalf("offline archive retained forbidden path %s", header.Name)
		}
	}
}

func archiveDifference(t *testing.T, left, right []byte) string {
	t.Helper()
	read := func(encoded []byte) map[string]string {
		result := make(map[string]string)
		gzipReader, err := gzip.NewReader(bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		defer gzipReader.Close()
		tarReader := tar.NewReader(gzipReader)
		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			contents, err := io.ReadAll(tarReader)
			if err != nil {
				t.Fatal(err)
			}
			result[header.Name] = fmt.Sprintf("%x", sha256.Sum256(contents))
		}
		return result
	}
	leftEntries, rightEntries := read(left), read(right)
	var differences []string
	for name, digest := range leftEntries {
		if rightEntries[name] != digest {
			differences = append(differences, name+":"+digest+"->"+rightEntries[name])
		}
	}
	for name := range rightEntries {
		if _, exists := leftEntries[name]; !exists {
			differences = append(differences, "+"+name)
		}
	}
	sort.Strings(differences)
	return strings.Join(differences, ",")
}

const snapshotAPTConfig = `schema: sow/v1
state: {snapshot_materialization_months: 1}
gpg:
  public_key: repository-public.pgp
pools:
  public: {}
  gated: {}
repos:
  - id: deb-test
    type: apt
    path: apt/test
    default_pool: public
    arches: [arm64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`

const snapshotYUMConfig = `schema: sow/v1
state: {snapshot_materialization_months: 6}
gpg:
  public_key: repository-public.pgp
pools:
  public: {}
  gated: {}
repos:
  - id: rpm-test
    type: yum
    path: yum/test/x86_64
    default_pool: public
    arches: [x86_64]
    os: {family: el, major: 10, lifecycle: active}
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
