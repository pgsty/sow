package upstream

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/klauspost/compress/zstd"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/syncer"
	"github.com/pgsty/sow/internal/yumrepo"
	"github.com/ulikunitz/xz"
)

type protocolServer struct {
	mu        sync.RWMutex
	files     map[string][]byte
	failOnce  map[string]bool
	rangeSeen map[string]bool
}

func newProtocolServer() *protocolServer {
	return &protocolServer{files: make(map[string][]byte), failOnce: make(map[string]bool), rangeSeen: make(map[string]bool)}
}

func (s *protocolServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/")
	s.mu.Lock()
	body, ok := s.files[key]
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	body = append([]byte(nil), body...)
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		s.rangeSeen[key] = true
	}
	shouldFail := s.failOnce[key] && rangeHeader == ""
	if shouldFail {
		s.failOnce[key] = false
	}
	s.mu.Unlock()

	if shouldFail {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body[:len(body)/2])
		return
	}
	if rangeHeader != "" {
		if !strings.HasPrefix(rangeHeader, "bytes=") || !strings.HasSuffix(rangeHeader, "-") {
			http.Error(w, "bad range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		offset, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rangeHeader, "bytes="), "-"))
		if err != nil || offset < 0 || offset > len(body) {
			http.Error(w, "bad range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, len(body)-1, len(body)))
		w.Header().Set("Content-Length", strconv.Itoa(len(body)-offset))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(body[offset:])
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *protocolServer) set(files map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, value := range files {
		s.files[key] = append([]byte(nil), value...)
	}
}

func (s *protocolServer) delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.files, key)
}

func (s *protocolServer) failNext(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failOnce[key] = true
}

func (s *protocolServer) sawRange(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rangeSeen[key]
}

type testSigning struct {
	entity    *openpgp.Entity
	aptSigner *aptrepo.Signer
	yumSigner *yumrepo.OpenPGPKey
	signedAt  time.Time
}

func newTestSigning(t *testing.T) testSigning {
	t.Helper()
	created := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)
	signedAt := created.Add(time.Hour)
	config := &packet.Config{DefaultHash: crypto.SHA256, RSABits: 1024, Time: func() time.Time { return created }}
	entity, err := openpgp.NewEntity("SOW Upstream Test", "", "sow@example.invalid", config)
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	armored, err := armor.Encode(&private, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(armored, config); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	aptSigner, err := aptrepo.NewSignerBytes(private.Bytes(), nil)
	if err != nil {
		t.Fatalf("apt signer: %v", err)
	}
	yumSigner, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(private.Bytes()), nil, signedAt)
	if err != nil {
		t.Fatalf("yum signer: %v", err)
	}
	return testSigning{entity: entity, aptSigner: aptSigner, yumSigner: yumSigner, signedAt: signedAt}
}

type aptPackageFixture struct {
	name, version, arch, filename string
	body                          []byte
}

func publishAPTFixture(t *testing.T, server *protocolServer, signing testSigning, packages []aptPackageFixture) {
	t.Helper()
	sort.Slice(packages, func(i, j int) bool { return packages[i].name < packages[j].name })
	var paragraphs bytes.Buffer
	files := make(map[string][]byte)
	for _, pkg := range packages {
		sum := sha256.Sum256(pkg.body)
		fmt.Fprintf(&paragraphs, "Package: %s\nVersion: %s\nArchitecture: %s\nFilename: %s\nSize: %d\nSHA256: %s\n\n",
			pkg.name, pkg.version, pkg.arch, pkg.filename, len(pkg.body), hex.EncodeToString(sum[:]))
		files[pkg.filename] = pkg.body
	}
	var compressed bytes.Buffer
	xzWriter, err := xz.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xzWriter.Write(paragraphs.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := xzWriter.Close(); err != nil {
		t.Fatal(err)
	}
	index := compressed.Bytes()
	indexSum := sha256.Sum256(index)
	release := []byte(fmt.Sprintf("Suite: bookworm\nCodename: bookworm\nComponents: main\nArchitectures: amd64\nSHA256:\n %s %d main/binary-amd64/Packages.xz\n",
		hex.EncodeToString(indexSum[:]), len(index)))
	var inRelease bytes.Buffer
	if err := signing.aptSigner.ClearSign(&inRelease, bytes.NewReader(release), signing.signedAt); err != nil {
		t.Fatalf("clear sign Release: %v", err)
	}
	files["dists/bookworm/InRelease"] = inRelease.Bytes()
	files["dists/bookworm/main/binary-amd64/Packages.xz"] = index
	server.set(files)
}

func switchAPTToDetachedRelease(t *testing.T, server *protocolServer, signing testSigning) {
	t.Helper()
	server.mu.RLock()
	inRelease := append([]byte(nil), server.files["dists/bookworm/InRelease"]...)
	server.mu.RUnlock()
	block, rest := clearsign.Decode(inRelease)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("fixture InRelease could not be decoded")
	}
	var signature bytes.Buffer
	if err := signing.aptSigner.DetachedSign(&signature, bytes.NewReader(block.Plaintext), signing.signedAt); err != nil {
		t.Fatal(err)
	}
	server.set(map[string][]byte{
		"dists/bookworm/Release":     block.Plaintext,
		"dists/bookworm/Release.gpg": signature.Bytes(),
	})
	server.delete("dists/bookworm/InRelease")
}

type emptyInventory struct{}

func (emptyInventory) Has(string, int64) (bool, error) { return false, nil }

type hashInventory map[string]int64

func (inventory hashInventory) Has(hash string, size int64) (bool, error) {
	want, ok := inventory[hash]
	return ok && want == size, nil
}

type fileInventoryEntry struct {
	path string
	size int64
}

type fileInventory struct {
	entries map[string]fileInventoryEntry
	opens   *int
}

func loadRPMPackageTrust(t *testing.T, paths ...string) (openpgp.EntityList, string) {
	t.Helper()
	hasher := sha256.New()
	var entities openpgp.EntityList
	for _, filename := range paths {
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		var parsed openpgp.EntityList
		if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN PGP")) {
			parsed, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
		} else {
			parsed, err = openpgp.ReadKeyRing(bytes.NewReader(data))
		}
		if err != nil || len(parsed) == 0 {
			t.Fatalf("parse RPM package keyring %s: entities=%d err=%v", filename, len(parsed), err)
		}
		entities = append(entities, parsed...)
		_, _ = hasher.Write(data)
		_, _ = hasher.Write([]byte{0})
	}
	return entities, hex.EncodeToString(hasher.Sum(nil))
}

func (inventory fileInventory) Has(hash string, size int64) (bool, error) {
	entry, ok := inventory.entries[hash]
	return ok && entry.size == size, nil
}

func (inventory fileInventory) OpenArtifact(hash string, size int64) (io.ReadSeekCloser, error) {
	entry, ok := inventory.entries[hash]
	if !ok || entry.size != size {
		return nil, os.ErrNotExist
	}
	if inventory.opens != nil {
		*inventory.opens++
	}
	return os.Open(entry.path)
}

func TestAPTDiscoveryExecutorResumeAndAdditiveDeletion(t *testing.T) {
	signing := newTestSigning(t)
	handler := newProtocolServer()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	foo := aptPackageFixture{name: "foo", version: "1.2-3", arch: "amd64", filename: "pool/main/f/foo/foo_1.2-3_amd64.deb", body: bytes.Repeat([]byte("foo-body-"), 8192)}
	debug := aptPackageFixture{name: "foo-dbgsym", version: "1.2-3", arch: "amd64", filename: "pool/main/f/foo/foo-dbgsym_1.2-3_amd64.deb", body: []byte("debug-body")}
	publishAPTFixture(t, handler, signing, []aptPackageFixture{foo, debug})

	work := t.TempDir()
	source := APTSource{
		BaseURL: server.URL + "/", Suite: "bookworm", Components: []string{"main"}, Architectures: []string{"amd64"},
		Keyring: openpgp.EntityList{signing.entity}, Client: server.Client(), WorkDir: filepath.Join(work, "metadata"),
	}
	discovery, err := DiscoverAPT(context.Background(), source)
	if err != nil {
		t.Fatalf("DiscoverAPT: %v", err)
	}
	if len(discovery.Candidates) != 2 || len(discovery.Evidence) != 2 {
		t.Fatalf("discovery candidates/evidence = %d/%d", len(discovery.Candidates), len(discovery.Evidence))
	}
	var fooCandidate syncer.Candidate
	for _, candidate := range discovery.Candidates {
		if candidate.Name == "foo" {
			fooCandidate = candidate
		}
	}
	if fooCandidate.Name == "" {
		t.Fatal("foo candidate absent")
	}
	receipt, err := discovery.Receipt(fooCandidate, signing.signedAt)
	if err != nil || receipt.DEB == nil || receipt.DEB.SignedReleaseKind != "InRelease" {
		t.Fatalf("DEB receipt = %#v, %v", receipt, err)
	}
	mutated := fooCandidate
	mutated.URL = server.URL + "/pool/main/f/foo/different.deb"
	if _, err := discovery.Receipt(mutated, signing.signedAt); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("mutated candidate received provenance: %v", err)
	}
	switchAPTToDetachedRelease(t, handler, signing)
	detached, err := DiscoverAPT(context.Background(), source)
	if err != nil {
		t.Fatalf("DiscoverAPT Release+Release.gpg: %v", err)
	}
	detachedReceipt, err := detached.Receipt(detached.Candidates[0], signing.signedAt)
	if err != nil || detachedReceipt.DEB == nil || detachedReceipt.DEB.SignedReleaseKind != "Release+Release.gpg" || len(detached.Evidence) != 3 {
		t.Fatalf("detached APT proof/evidence = %#v/%d, %v", detachedReceipt.DEB, len(detached.Evidence), err)
	}
	// Restore InRelease so the resume half also exercises that path.
	publishAPTFixture(t, handler, signing, []aptPackageFixture{foo, debug})
	deniedPlan, err := syncer.BuildPlan(discovery.Candidates, syncer.Filter{
		Allow: []string{"foo*"}, Deny: []string{"foo-dbgsym@amd64"}, DebugInfo: "keep",
	}, emptyInventory{})
	if err != nil || len(deniedPlan.Download) != 1 || deniedPlan.Download[0].Name != "foo" || deniedPlan.Filtered != 1 {
		t.Fatalf("name+arch allow/deny plan = %#v, %v", deniedPlan, err)
	}
	handler.failNext(foo.filename)
	store := provenance.NewStore(filepath.Join(work, "state"))
	executor := Executor{
		Downloader: syncer.Downloader{Client: server.Client(), Attempts: 3}, DownloadDir: filepath.Join(work, "packages"),
		Provenance: store, Workers: 2, Now: func() time.Time { return signing.signedAt },
	}
	result, err := executor.Run(context.Background(), discovery, syncer.Filter{Allow: []string{"foo@amd64"}, DebugInfo: "drop"}, emptyInventory{})
	if err != nil {
		t.Fatalf("executor.Run: %v", err)
	}
	if len(result.Downloaded) != 1 || result.Plan.Filtered != 1 || !handler.sawRange(foo.filename) {
		t.Fatalf("downloaded=%d filtered=%d range=%v", len(result.Downloaded), result.Plan.Filtered, handler.sawRange(foo.filename))
	}
	downloaded, err := os.ReadFile(result.Downloaded[0].Path)
	if err != nil || !bytes.Equal(downloaded, foo.body) {
		t.Fatalf("download bytes mismatch: %v", err)
	}
	if _, err := store.Get("deb", fooCandidate.SHA256); err != nil {
		t.Fatalf("provenance not committed: %v", err)
	}
	presentExecutor := executor
	presentExecutor.Provenance = provenance.NewStore(filepath.Join(work, "adopted-state"))
	presentResult, err := presentExecutor.Run(context.Background(), discovery,
		syncer.Filter{Allow: []string{"foo@amd64"}, DebugInfo: "drop"},
		fileInventory{entries: map[string]fileInventoryEntry{fooCandidate.SHA256: {path: result.Downloaded[0].Path, size: fooCandidate.Size}}})
	if err != nil || len(presentResult.Downloaded) != 0 || len(presentResult.Present) != 1 || !presentResult.Present[0].NewReceipt {
		t.Fatalf("present artifact provenance adoption = %#v, %v", presentResult, err)
	}
	executor.Now = func() time.Time { return signing.signedAt.Add(time.Hour) }
	replayed, err := executor.Run(context.Background(), discovery, syncer.Filter{Allow: []string{"foo@amd64"}, DebugInfo: "drop"}, emptyInventory{})
	if err != nil || len(replayed.Downloaded) != 1 || replayed.Downloaded[0].NewReceipt {
		t.Fatalf("idempotent resume/replay = %#v, %v", replayed, err)
	}

	// The next signed upstream snapshot removes foo. Discovery becomes empty,
	// but the additive executor has no delete operation and leaves local bytes.
	publishAPTFixture(t, handler, signing, nil)
	removedDiscovery, err := DiscoverAPT(context.Background(), source)
	if err != nil {
		t.Fatalf("DiscoverAPT after upstream deletion: %v", err)
	}
	if len(removedDiscovery.Candidates) != 0 {
		t.Fatalf("removed upstream still exposed %d candidates", len(removedDiscovery.Candidates))
	}
	second, err := executor.Run(context.Background(), removedDiscovery, syncer.Filter{DebugInfo: "drop"}, emptyInventory{})
	if err != nil || len(second.Downloaded) != 0 {
		t.Fatalf("additive replay = %#v, %v", second, err)
	}
	if got, err := os.ReadFile(result.Downloaded[0].Path); err != nil || !bytes.Equal(got, foo.body) {
		t.Fatalf("local package was deleted or changed: %v", err)
	}
}

func TestAPTExecutorRetainsFirstReceiptAcrossSignedIndexRotation(t *testing.T) {
	signing := newTestSigning(t)
	handler := newProtocolServer()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	oldPackage := aptPackageFixture{name: "old", version: "1", arch: "amd64", filename: "pool/main/o/old/old_1_amd64.deb", body: []byte("retained-deb")}
	newPackage := aptPackageFixture{name: "new", version: "2", arch: "amd64", filename: "pool/main/n/new/new_2_amd64.deb", body: []byte("new-deb")}
	publishAPTFixture(t, handler, signing, []aptPackageFixture{oldPackage})
	work := t.TempDir()
	source := APTSource{
		BaseURL: server.URL + "/", Suite: "bookworm", Components: []string{"main"}, Architectures: []string{"amd64"},
		Keyring: openpgp.EntityList{signing.entity}, Client: server.Client(), WorkDir: filepath.Join(work, "metadata-1"),
	}
	first, err := DiscoverAPT(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	store := provenance.NewStore(filepath.Join(work, "state"))
	executor := Executor{
		Downloader: syncer.Downloader{Client: server.Client(), Attempts: 1}, DownloadDir: filepath.Join(work, "packages"),
		Provenance: store, Workers: 1, Now: func() time.Time { return signing.signedAt },
	}
	firstResult, err := executor.Run(context.Background(), first, syncer.Filter{DebugInfo: "keep"}, emptyInventory{})
	if err != nil || len(firstResult.Downloaded) != 1 {
		t.Fatalf("first APT execution=%+v err=%v", firstResult, err)
	}
	oldCandidate := first.Candidates[0]
	firstReceipt, err := store.Get("deb", oldCandidate.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	firstCanonical, err := firstReceipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}

	publishAPTFixture(t, handler, signing, []aptPackageFixture{oldPackage, newPackage})
	source.WorkDir = filepath.Join(work, "metadata-2")
	second, err := DiscoverAPT(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	oldRecord, err := second.store.get(oldCandidate.SHA256)
	if err != nil || oldRecord.Proof.deb.PackagesEvidenceSHA256 == firstReceipt.DEB.PackagesEvidenceSHA256 {
		t.Fatalf("APT index did not rotate: proof=%+v err=%v", oldRecord.Proof.deb, err)
	}
	executor.Now = func() time.Time { return signing.signedAt.Add(time.Hour) }
	secondResult, err := executor.Run(context.Background(), second, syncer.Filter{DebugInfo: "keep"}, hashInventory{oldCandidate.SHA256: oldCandidate.Size})
	if err != nil || len(secondResult.Present) != 1 || len(secondResult.Downloaded) != 1 {
		t.Fatalf("rotated APT execution=%+v err=%v", secondResult, err)
	}
	retained, err := store.Get("deb", oldCandidate.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	retainedCanonical, err := retained.CanonicalJSON()
	if err != nil || !bytes.Equal(firstCanonical, retainedCanonical) {
		t.Fatalf("first APT observation was rewritten: err=%v\nfirst=%s\nafter=%s", err, firstCanonical, retainedCanonical)
	}
	if _, err := store.Get("deb", secondResult.Downloaded[0].Candidate.SHA256); err != nil {
		t.Fatalf("new APT package receipt missing: %v", err)
	}
}

type rpmPackageFixture struct {
	name, arch, epoch, version, release, location string
	body                                          []byte
}

func publishYUMFixture(t *testing.T, server *protocolServer, signing testSigning, packages []rpmPackageFixture, maliciousDTD bool) {
	t.Helper()
	var primary bytes.Buffer
	fmt.Fprintf(&primary, `<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="%d">
`, len(packages))
	files := make(map[string][]byte)
	for _, pkg := range packages {
		sum := sha256.Sum256(pkg.body)
		fmt.Fprintf(&primary, `<package type="rpm"><name>%s</name><arch>%s</arch><version epoch="%s" ver="%s" rel="%s"/><checksum type="sha256" pkgid="YES">%s</checksum><size package="%d" installed="1" archive="1"/><location href="%s"/><format xmlns:rpm="http://linux.duke.edu/metadata/rpm"/></package>
`, pkg.name, pkg.arch, pkg.epoch, pkg.version, pkg.release, hex.EncodeToString(sum[:]), len(pkg.body), pkg.location)
		files[pkg.location] = pkg.body
	}
	primary.WriteString("</metadata>\n")
	var compressed bytes.Buffer
	zstdWriter, err := zstd.NewWriter(&compressed, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zstdWriter.Write(primary.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zstdWriter.Close(); err != nil {
		t.Fatal(err)
	}
	compressedSum := sha256.Sum256(compressed.Bytes())
	openSum := sha256.Sum256(primary.Bytes())
	repomd := []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision><data type="primary"><checksum type="sha256">%s</checksum><open-checksum type="sha256">%s</open-checksum><location href="repodata/primary.xml.zst"/><timestamp>1</timestamp><size>%d</size><open-size>%d</open-size></data></repomd>
`, hex.EncodeToString(compressedSum[:]), hex.EncodeToString(openSum[:]), compressed.Len(), primary.Len()))
	if maliciousDTD {
		repomd = bytes.Replace(repomd, []byte("<repomd "), []byte("<!DOCTYPE repomd [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<repomd "), 1)
	}
	var signature bytes.Buffer
	if err := signing.yumSigner.Sign(context.Background(), bytes.NewReader(repomd), &signature); err != nil {
		t.Fatalf("sign repomd: %v", err)
	}
	files["repodata/repomd.xml"] = repomd
	files["repodata/repomd.xml.asc"] = signature.Bytes()
	files["repodata/primary.xml.zst"] = compressed.Bytes()
	server.set(files)
}

func TestYUMDiscoveryVerifiesRepomdAndPrimary(t *testing.T) {
	signing := newTestSigning(t)
	handler := newProtocolServer()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	encoded, err := os.ReadFile("../cli/testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	rpmBody, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	rpm := rpmPackageFixture{name: "pgdg-redhat-nonfree-repo", arch: "noarch", epoch: "0", version: "42.0", release: "20PGDG", location: "Packages/p/pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm", body: rpmBody}
	publishYUMFixture(t, handler, signing, []rpmPackageFixture{rpm}, false)
	work := t.TempDir()
	discovery, err := DiscoverYUM(context.Background(), YUMSource{
		BaseURL: server.URL + "/", Keyring: openpgp.EntityList{signing.entity}, Client: server.Client(), WorkDir: filepath.Join(work, "metadata"),
	})
	if err != nil {
		t.Fatalf("DiscoverYUM: %v", err)
	}
	defer discovery.Close()
	if len(discovery.Candidates) != 1 || len(discovery.Evidence) != 3 {
		t.Fatalf("YUM candidates/evidence = %d/%d", len(discovery.Candidates), len(discovery.Evidence))
	}
	candidate := discovery.Candidates[0]
	if candidate.Name != rpm.name || candidate.Version != rpm.version+"-"+rpm.release {
		t.Fatalf("candidate identity = %#v", candidate)
	}
	if _, err := discovery.Receipt(candidate, signing.signedAt); err == nil || !strings.Contains(err.Error(), "embedded signature") {
		t.Fatalf("RPM receipt without inspected package signature = %v", err)
	}
	if !discovery.Evidence[0].Verified || !discovery.Evidence[1].Verified {
		t.Fatal("repomd signature evidence was not marked verified")
	}
	rpmKeyring, rpmKeyringSHA := loadRPMPackageTrust(t, "../../test/compat/testdata/PGDG-RPM-GPG-KEY-RHEL-nonfree.asc")
	yumStore := provenance.NewStore(filepath.Join(work, "state"))
	yumResult, err := (Executor{
		Downloader: syncer.Downloader{Client: server.Client(), Attempts: 2}, DownloadDir: filepath.Join(work, "packages"),
		Provenance: yumStore, Workers: 1, Now: func() time.Time { return signing.signedAt },
		RPMPackageKeyring: rpmKeyring, RPMPackageKeyringSHA256: rpmKeyringSHA,
	}).Run(context.Background(), discovery, syncer.Filter{DebugInfo: "keep"}, emptyInventory{})
	if err != nil || len(yumResult.Downloaded) != 1 {
		t.Fatalf("YUM package sync = %#v, %v", yumResult, err)
	}
	if body, err := os.ReadFile(yumResult.Downloaded[0].Path); err != nil || !bytes.Equal(body, rpm.body) {
		t.Fatalf("YUM package checksum/size download mismatch: %v", err)
	}
	if stored, err := yumStore.Get("rpm", candidate.SHA256); err != nil || stored.RPM == nil || stored.RPM.IndexSHA256 == "" ||
		stored.RPM.SignatureVerification != "verified" || stored.RPM.PackageKeyringSHA256 != rpmKeyringSHA ||
		len(stored.RPM.EmbeddedSignatures) == 0 || stored.RPM.EmbeddedSignatures[0].SignerFingerprint == "" {
		t.Fatalf("stored RPM provenance = %#v, %v", stored, err)
	}
	filtered, err := DiscoverYUMStreaming(context.Background(), YUMSource{
		BaseURL: server.URL + "/", Architectures: []string{"aarch64"}, Keyring: openpgp.EntityList{signing.entity},
		Client: server.Client(), WorkDir: filepath.Join(work, "filtered-metadata"),
	})
	if err != nil {
		t.Fatalf("streaming YUM architecture filter: %v", err)
	}
	// noarch packages are intentionally shared across every requested
	// architecture, so the signed repository-release RPM remains selected.
	if filtered.CandidateCount() != 1 || filtered.Candidates != nil {
		t.Fatalf("streaming YUM filter count=%d materialized=%d", filtered.CandidateCount(), len(filtered.Candidates))
	}
	if err := filtered.Close(); err != nil {
		t.Fatal(err)
	}
	separateBasearch, err := DiscoverYUMStreaming(context.Background(), YUMSource{
		BaseURL: server.URL + "/", Architectures: []string{"aarch64"}, ExcludeNoarch: true,
		Keyring: openpgp.EntityList{signing.entity}, Client: server.Client(), WorkDir: filepath.Join(work, "separate-basearch-metadata"),
	})
	if err != nil {
		t.Fatalf("streaming YUM separate-basearch filter: %v", err)
	}
	if separateBasearch.CandidateCount() != 0 || separateBasearch.Candidates != nil {
		t.Fatalf("separate basearch discovery retained noarch candidates count=%d materialized=%d", separateBasearch.CandidateCount(), len(separateBasearch.Candidates))
	}
	if err := separateBasearch.Close(); err != nil {
		t.Fatal(err)
	}

	publishYUMFixture(t, handler, signing, []rpmPackageFixture{rpm}, true)
	_, err = DiscoverYUM(context.Background(), YUMSource{
		BaseURL: server.URL + "/", Keyring: openpgp.EntityList{signing.entity}, Client: server.Client(), WorkDir: t.TempDir(),
	})
	if !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("signed DTD repomd error = %v", err)
	}
}

func TestYUMExecutorRetainsFirstReceiptAcrossSignedIndexRotation(t *testing.T) {
	signing := newTestSigning(t)
	handler := newProtocolServer()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	encoded, err := os.ReadFile("../cli/testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	oldBody, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	newBody, err := os.ReadFile("../../third_party/cavaliergopher-rpm/testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm")
	if err != nil {
		t.Fatal(err)
	}
	if signatures, inspectErr := yumrepo.InspectEmbeddedRPMSignatures(context.Background(), bytes.NewReader(newBody)); inspectErr != nil {
		t.Fatal(inspectErr)
	} else {
		t.Logf("CentOS fixture embedded signatures=%+v", signatures)
	}
	oldPackage := rpmPackageFixture{name: "old-rpm", arch: "noarch", epoch: "0", version: "1", release: "1", location: "Packages/o/old-rpm-1-1.noarch.rpm", body: oldBody}
	newPackage := rpmPackageFixture{name: "new-rpm", arch: "x86_64", epoch: "0", version: "2", release: "1", location: "Packages/n/new-rpm-2-1.x86_64.rpm", body: newBody}
	publishYUMFixture(t, handler, signing, []rpmPackageFixture{oldPackage}, false)
	work := t.TempDir()
	source := YUMSource{BaseURL: server.URL + "/", Keyring: openpgp.EntityList{signing.entity}, Client: server.Client(), WorkDir: filepath.Join(work, "metadata-1")}
	first, err := DiscoverYUM(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	rpmKeyring, rpmKeyringSHA := loadRPMPackageTrust(t,
		"../../test/compat/testdata/PGDG-RPM-GPG-KEY-RHEL-nonfree.asc",
		"../../third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-2",
		"../../third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-3",
		"../../third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-4",
		"../../third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-5",
		"../../third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-6",
		"../../third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-7",
	)
	store := provenance.NewStore(filepath.Join(work, "state"))
	executor := Executor{
		Downloader: syncer.Downloader{Client: server.Client(), Attempts: 1}, DownloadDir: filepath.Join(work, "packages"),
		Provenance: store, Workers: 1, Now: func() time.Time { return signing.signedAt },
		RPMPackageKeyring: rpmKeyring, RPMPackageKeyringSHA256: rpmKeyringSHA,
	}
	firstResult, err := executor.Run(context.Background(), first, syncer.Filter{DebugInfo: "keep"}, emptyInventory{})
	if err != nil || len(firstResult.Downloaded) != 1 {
		t.Fatalf("first YUM execution=%+v err=%v", firstResult, err)
	}
	oldCandidate := first.Candidates[0]
	firstReceipt, err := store.Get("rpm", oldCandidate.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	firstCanonical, err := firstReceipt.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	// A package-trust bundle identity change is part of the change set even
	// when the artifact digest is unchanged: force exact-body revalidation
	// before retaining the immutable first receipt.
	rotatedTrustExecutor := executor
	rotatedTrustExecutor.RPMPackageKeyringSHA256 = strings.Repeat("f", 64)
	trustRotationOpens := 0
	trustRotation, err := rotatedTrustExecutor.Run(context.Background(), first, syncer.Filter{DebugInfo: "keep"}, fileInventory{
		entries: map[string]fileInventoryEntry{oldCandidate.SHA256: {path: firstResult.Downloaded[0].Path, size: oldCandidate.Size}},
		opens:   &trustRotationOpens,
	})
	if err != nil || len(trustRotation.Present) != 1 || trustRotationOpens != 1 {
		t.Fatalf("RPM trust rotation revalidation=%+v opens=%d err=%v", trustRotation, trustRotationOpens, err)
	}

	publishYUMFixture(t, handler, signing, []rpmPackageFixture{oldPackage, newPackage}, false)
	source.WorkDir = filepath.Join(work, "metadata-2")
	second, err := DiscoverYUM(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	oldRecord, err := second.store.get(oldCandidate.SHA256)
	if err != nil || oldRecord.Proof.rpm.IndexSHA256 == firstReceipt.RPM.IndexSHA256 {
		t.Fatalf("YUM primary did not rotate: proof=%+v err=%v", oldRecord.Proof.rpm, err)
	}
	executor.Now = func() time.Time { return signing.signedAt.Add(time.Hour) }
	secondResult, err := executor.Run(context.Background(), second, syncer.Filter{DebugInfo: "keep"}, hashInventory{oldCandidate.SHA256: oldCandidate.Size})
	if err != nil || len(secondResult.Present) != 1 || len(secondResult.Downloaded) != 1 {
		t.Fatalf("rotated YUM execution=%+v err=%v", secondResult, err)
	}
	retained, err := store.Get("rpm", oldCandidate.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	retainedCanonical, err := retained.CanonicalJSON()
	if err != nil || !bytes.Equal(firstCanonical, retainedCanonical) {
		t.Fatalf("first YUM observation was rewritten: err=%v\nfirst=%s\nafter=%s", err, firstCanonical, retainedCanonical)
	}
	if _, err := store.Get("rpm", secondResult.Downloaded[0].Candidate.SHA256); err != nil {
		t.Fatalf("new YUM package receipt missing: %v", err)
	}
}

func TestPresentRPMMustHashExactCandidateBytesBeforeProvenance(t *testing.T) {
	encoded, err := os.ReadFile("../cli/testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	actual := sha256.Sum256(body)
	fakeDigest := strings.Repeat("0", 64)
	if fakeDigest == hex.EncodeToString(actual[:]) {
		t.Fatal("test digest unexpectedly matches RPM body")
	}
	candidate := syncer.Candidate{
		Format: "rpm", Name: "pgdg-redhat-nonfree-repo", Version: "42.0-20PGDG", Arch: "noarch",
		URL: "https://example.invalid/Packages/p/pgdg-redhat-nonfree-repo.rpm", Size: int64(len(body)), SHA256: fakeDigest,
	}
	discovery, err := newDiscovery("rpm", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer discovery.Close()
	proof := provenance.RPMProof{
		IndexURL: "https://example.invalid/repodata/primary.xml.zst", IndexSHA256: strings.Repeat("1", 64), IndexSize: 1,
		OriginalRPMSHA: fakeDigest, SignaturePolicy: "preserve-upstream",
	}
	if err := discovery.store.add(candidate, candidateProof{rpm: &proof}); err != nil {
		t.Fatal(err)
	}
	if err := discovery.store.finalize(); err != nil {
		t.Fatal(err)
	}
	discovery.count = 1
	keyring, keyringSHA := loadRPMPackageTrust(t, "../../test/compat/testdata/PGDG-RPM-GPG-KEY-RHEL-nonfree.asc")
	_, err = receiptForArtifact(context.Background(), discovery, candidate, time.Now().UTC(), bytes.NewReader(body), keyring, keyringSHA)
	if !errors.Is(err, ErrEvidence) || !strings.Contains(err.Error(), "body digest/size mismatch") {
		t.Fatalf("same-size signed RPM at the wrong digest coordinate was accepted: %v", err)
	}
}

func TestPresentDEBMustHashExactCandidateBytesBeforeProvenance(t *testing.T) {
	body := []byte("same-size-corrupt-deb-body")
	actual := sha256.Sum256(body)
	fakeDigest := strings.Repeat("0", 64)
	if fakeDigest == hex.EncodeToString(actual[:]) {
		t.Fatal("test digest unexpectedly matches DEB body")
	}
	candidate := syncer.Candidate{
		Format: "deb", Name: "example", Version: "1", Arch: "amd64",
		URL: "https://example.invalid/pool/e/example_1_amd64.deb", Size: int64(len(body)), SHA256: fakeDigest,
	}
	discovery, err := newDiscovery("deb", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer discovery.Close()
	proof := provenance.DEBProof{
		PackagesEntrySHA256: strings.Repeat("1", 64), PackagesEvidenceSHA256: strings.Repeat("2", 64),
		SignedReleaseSHA256: strings.Repeat("3", 64), SignedReleaseKind: "InRelease",
	}
	if err := discovery.store.add(candidate, candidateProof{deb: &proof}); err != nil {
		t.Fatal(err)
	}
	if err := discovery.store.finalize(); err != nil {
		t.Fatal(err)
	}
	discovery.count = 1
	_, err = receiptForArtifact(context.Background(), discovery, candidate, time.Now().UTC(), bytes.NewReader(body), nil, "")
	if !errors.Is(err, ErrEvidence) || !strings.Contains(err.Error(), "body digest/size mismatch") {
		t.Fatalf("same-size DEB at the wrong digest coordinate was accepted: %v", err)
	}
}

func TestLegacyRPMReceiptEvidenceRemainsReplayCompatibleAfterInspection(t *testing.T) {
	legacy := provenance.Receipt{
		Schema: provenance.LegacySchema, Format: "rpm", ArtifactSHA256: strings.Repeat("a", 64), ArtifactSize: 42,
		UpstreamURL: "https://example.invalid/pkg.rpm", ObservedAt: time.Unix(1_700_000_000, 0).UTC(),
		RPM: &provenance.RPMProof{
			IndexURL: "https://example.invalid/repodata/primary.xml.zst", IndexSHA256: strings.Repeat("b", 64),
			IndexSize: 12, OriginalRPMSHA: strings.Repeat("a", 64), SignaturePolicy: "preserve-upstream",
		},
	}
	if err := legacy.Validate(); err != nil {
		t.Fatal(err)
	}
	current := legacy
	current.Schema = provenance.PreviousSchema
	current.UpstreamURL = "https://mirror.example.invalid/pkg.rpm"
	current.RPM = &provenance.RPMProof{
		IndexURL: "https://mirror.example.invalid/repodata/primary-2.xml.zst", IndexSHA256: strings.Repeat("d", 64), IndexSize: 99,
		OriginalRPMSHA: legacy.RPM.OriginalRPMSHA, SignaturePolicy: legacy.RPM.SignaturePolicy,
		EmbeddedSignatures: []provenance.RPMSignatureEvidence{{
			HeaderTag: "RPMSIGTAG_RSA", HeaderTagID: 268, PacketSHA256: strings.Repeat("c", 64), PacketSize: 256,
			PacketVersion: 4, PublicKeyAlgorithm: 1, HashAlgorithm: 8,
		}}, SignatureVerification: "not-performed",
	}
	if err := current.Validate(); err != nil {
		t.Fatal(err)
	}
	if !sameReceiptEvidence(legacy, current) || !sameReceiptEvidence(current, legacy) {
		t.Fatal("legacy receipt is not replay-compatible with newly inspected signature evidence")
	}
	rotatedV2 := current
	rotatedV2.UpstreamURL = "https://third.example.invalid/pkg.rpm"
	rotatedV2.RPM = new(provenance.RPMProof)
	*rotatedV2.RPM = *current.RPM
	rotatedV2.RPM.IndexSHA256 = strings.Repeat("e", 64)
	if !sameReceiptEvidence(current, rotatedV2) || !sameReceiptEvidence(rotatedV2, current) {
		t.Fatal("v2 RPM receipt conflicted on normal signed-index rotation")
	}
	tampered := rotatedV2
	tampered.RPM = new(provenance.RPMProof)
	*tampered.RPM = *rotatedV2.RPM
	tampered.RPM.EmbeddedSignatures = append([]provenance.RPMSignatureEvidence(nil), rotatedV2.RPM.EmbeddedSignatures...)
	tampered.RPM.EmbeddedSignatures[0].PacketSHA256 = strings.Repeat("f", 64)
	if sameReceiptEvidence(current, tampered) {
		t.Fatal("v2 RPM replay ignored changed body-derived signature evidence")
	}
	legacyRotated := legacy
	legacyRotated.UpstreamURL = "https://legacy-mirror.example.invalid/pkg.rpm"
	legacyRotated.RPM = new(provenance.RPMProof)
	*legacyRotated.RPM = *legacy.RPM
	legacyRotated.RPM.IndexSHA256 = strings.Repeat("e", 64)
	if !sameReceiptEvidence(legacy, legacyRotated) || !sameReceiptEvidence(legacyRotated, legacy) {
		t.Fatal("v1 RPM receipt conflicted on normal signed-index rotation")
	}
	store := provenance.NewStore(t.TempDir())
	if _, created, err := store.Put(legacy); err != nil || !created {
		t.Fatalf("store legacy receipt: created=%v err=%v", created, err)
	}
	candidate := syncer.Candidate{
		Format: "rpm", Name: "pkg", Version: "1-1", Arch: "x86_64", URL: legacy.UpstreamURL,
		Size: legacy.ArtifactSize, SHA256: legacy.ArtifactSHA256,
	}
	committed, err := commitReceipt(store, candidate, "", current)
	if err != nil || committed.NewReceipt {
		t.Fatalf("legacy replay created a competing v2 receipt: %+v err=%v", committed, err)
	}
	retained, err := store.Get("rpm", legacy.ArtifactSHA256)
	if err != nil || retained.Schema != provenance.LegacySchema {
		t.Fatalf("legacy replay did not retain canonical v1 receipt: schema=%q err=%v", retained.Schema, err)
	}
	v2Store := provenance.NewStore(t.TempDir())
	if _, created, err := v2Store.Put(current); err != nil || !created {
		t.Fatalf("store v2 receipt: created=%v err=%v", created, err)
	}
	if committed, err := commitReceipt(v2Store, candidate, "", legacyRotated); err != nil || committed.NewReceipt {
		t.Fatalf("v1 replay replaced canonical v2 receipt: %+v err=%v", committed, err)
	}
	if retained, err := v2Store.Get("rpm", legacy.ArtifactSHA256); err != nil || retained.Schema != provenance.PreviousSchema {
		t.Fatalf("v1 replay did not retain canonical v2 receipt: schema=%q err=%v", retained.Schema, err)
	}
}

func TestLegacyDEBReceiptEvidenceRemainsReplayCompatibleWithV2Marker(t *testing.T) {
	legacy := provenance.NewDEB(
		strings.Repeat("a", 64), 42, "https://example.invalid/pkg.deb", time.Unix(1_700_000_000, 0).UTC(),
		provenance.DEBProof{
			PackagesEntrySHA256: strings.Repeat("b", 64), PackagesEvidenceSHA256: strings.Repeat("c", 64),
			SignedReleaseSHA256: strings.Repeat("d", 64), SignedReleaseKind: "InRelease",
		},
	)
	current := legacy
	current.UpstreamURL = "https://mirror.example.invalid/pkg.deb"
	current.DEB = new(provenance.DEBProof)
	*current.DEB = *legacy.DEB
	current.DEB.PackagesEntrySHA256 = strings.Repeat("e", 64)
	current.DEB.PackagesEvidenceSHA256 = strings.Repeat("f", 64)
	current.DEB.SignedReleaseSHA256 = strings.Repeat("1", 64)
	legacy.Schema = provenance.LegacySchema
	if err := legacy.Validate(); err != nil {
		t.Fatal(err)
	}
	if !sameReceiptEvidence(legacy, current) || !sameReceiptEvidence(current, legacy) {
		t.Fatal("rotated v2 DEB observation is not replay-compatible with v1")
	}
	rotatedV2 := current
	rotatedV2.UpstreamURL = "https://third.example.invalid/pkg.deb"
	rotatedV2.DEB = new(provenance.DEBProof)
	*rotatedV2.DEB = *current.DEB
	rotatedV2.DEB.PackagesEvidenceSHA256 = strings.Repeat("2", 64)
	if !sameReceiptEvidence(current, rotatedV2) || !sameReceiptEvidence(rotatedV2, current) {
		t.Fatal("v2 DEB receipt conflicted on normal signed metadata rotation")
	}
	store := provenance.NewStore(t.TempDir())
	if _, created, err := store.Put(legacy); err != nil || !created {
		t.Fatalf("store legacy DEB receipt: created=%v err=%v", created, err)
	}
	candidate := syncer.Candidate{
		Format: "deb", Name: "pkg", Version: "1", Arch: "amd64", URL: legacy.UpstreamURL,
		Size: legacy.ArtifactSize, SHA256: legacy.ArtifactSHA256,
	}
	committed, err := commitReceipt(store, candidate, "", current)
	if err != nil || committed.NewReceipt {
		t.Fatalf("legacy DEB replay created a competing v2 receipt: %+v err=%v", committed, err)
	}
	retained, err := store.Get("deb", legacy.ArtifactSHA256)
	if err != nil || retained.Schema != provenance.LegacySchema {
		t.Fatalf("legacy DEB replay did not retain canonical v1 receipt: schema=%q err=%v", retained.Schema, err)
	}
	v2Store := provenance.NewStore(t.TempDir())
	if _, created, err := v2Store.Put(current); err != nil || !created {
		t.Fatalf("store v2 DEB receipt: created=%v err=%v", created, err)
	}
	if committed, err := commitReceipt(v2Store, candidate, "", legacy); err != nil || committed.NewReceipt {
		t.Fatalf("v1 DEB replay replaced canonical v2 receipt: %+v err=%v", committed, err)
	}
	if retained, err := v2Store.Get("deb", legacy.ArtifactSHA256); err != nil || retained.Schema != provenance.Schema {
		t.Fatalf("v1 DEB replay did not retain canonical v2 receipt: schema=%q err=%v", retained.Schema, err)
	}
}

func TestPureGoCompressionAndExpansionLimit(t *testing.T) {
	payload := bytes.Repeat([]byte("bounded-metadata\n"), 8192)
	tests := []struct {
		name string
		ext  string
		make func(*bytes.Buffer) io.WriteCloser
	}{
		{name: "gzip", ext: ".gz", make: func(out *bytes.Buffer) io.WriteCloser { w := gzip.NewWriter(out); return w }},
		{name: "xz", ext: ".xz", make: func(out *bytes.Buffer) io.WriteCloser {
			w, err := xz.NewWriter(out)
			if err != nil {
				t.Fatal(err)
			}
			return w
		}},
		{name: "zstd", ext: ".zst", make: func(out *bytes.Buffer) io.WriteCloser {
			w, err := zstd.NewWriter(out, zstd.WithEncoderConcurrency(1))
			if err != nil {
				t.Fatal(err)
			}
			return w
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var compressed bytes.Buffer
			writer := test.make(&compressed)
			if _, err := writer.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(t.TempDir(), "index"+test.ext)
			if err := os.WriteFile(filename, compressed.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			limits := (Limits{IndexUncompressedBytes: int64(len(payload)), XZDictionaryBytes: 64 << 20, ZstdMemoryBytes: 64 << 20}).withDefaults()
			stream, err := openIndex(filename, "https://repo.invalid/index"+test.ext, limits)
			if err != nil {
				t.Fatal(err)
			}
			got, readErr := io.ReadAll(stream)
			closeErr := stream.Close()
			if readErr != nil || closeErr != nil || !bytes.Equal(got, payload) {
				t.Fatalf("round trip read=%v close=%v bytes=%d", readErr, closeErr, len(got))
			}

			limits.IndexUncompressedBytes = int64(len(payload) - 1)
			stream, err = openIndex(filename, "https://repo.invalid/index"+test.ext, limits)
			if err != nil {
				t.Fatal(err)
			}
			_, readErr = io.ReadAll(stream)
			_ = stream.Close()
			if !errors.Is(readErr, ErrMetadataTooLarge) {
				t.Fatalf("expansion limit error = %v", readErr)
			}
		})
	}
}

func TestURLAndAPTPathHardening(t *testing.T) {
	if _, err := normalizeBase("https://repo.invalid/a/../private/"); !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("non-canonical base URL error = %v", err)
	}
	base, err := normalizeBase("https://repo.invalid/public/")
	if err != nil {
		t.Fatal(err)
	}
	stanza := "Package: escape\nVersion: 1\nArchitecture: amd64\nFilename: ../secret.deb\nSize: 1\nSHA256: " + strings.Repeat("0", 64) + "\n"
	err = parseDebPackages(strings.NewReader(stanza), base, 4096, func(syncer.Candidate, string) error { return nil })
	if !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("traversal Packages error = %v", err)
	}
	oversized := "Package: " + strings.Repeat("x", 8192) + "\n"
	err = parseDebPackages(strings.NewReader(oversized), base, 4096, func(syncer.Candidate, string) error { return nil })
	if !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("oversized stanza error = %v", err)
	}

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("secret")) }))
	defer plain.Close()
	tlsRedirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/metadata", http.StatusFound)
	}))
	defer tlsRedirect.Close()
	_, _, err = fetchBytes(context.Background(), tlsRedirect.Client(), tlsRedirect.URL+"/Release", 1024, false)
	if !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("HTTPS downgrade redirect error = %v", err)
	}
}
