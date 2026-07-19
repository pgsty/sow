package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

func TestCompatibilityContentRootRequiresExactCandidate(t *testing.T) {
	shaA := strings.Repeat("a", 64)
	shaB := strings.Repeat("b", 64)
	candidate := "Packages/p/pkg.rpm\t7\t" + shaA + "\n" +
		"repodata/repomd.xml\t9\t" + shaB + "\n"
	rooted := "yum/infra/x86_64/Packages/p/pkg.rpm\t7\t" + shaA + "\n" +
		"yum/infra/x86_64/repodata/repomd.xml\t9\t" + shaB + "\n"
	identity := pub.CompatibilityState{ID: "infra-legacy", RouteRoot: "yum/infra/x86_64"}

	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{name: "exact", content: rooted},
		{name: "missing", content: "yum/infra/x86_64/Packages/p/pkg.rpm\t7\t" + shaA + "\n", wantErr: true},
		{name: "extra", content: rooted + "yum/infra/x86_64/z-extra.rpm\t1\t" + shaA + "\n", wantErr: true},
		{name: "tampered", content: strings.Replace(rooted, "\t7\t"+shaA, "\t8\t"+shaA, 1), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			canonical := state.New(filepath.Join(t.TempDir(), ".sow"))
			candidateFile := filepath.Join(t.TempDir(), "candidate.tsv")
			contentFile := filepath.Join(t.TempDir(), "content.tsv")
			if err := os.WriteFile(candidateFile, []byte(candidate), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(contentFile, []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(identity.ID)
			commit, changed, err := canonical.InstallPaths(map[string]string{
				candidatePath:                        candidateFile,
				remoteStatePath("cf", "content.tsv"): contentFile,
			}, "test: compatibility content closure")
			if err != nil || !changed {
				t.Fatalf("install closure changed=%t err=%v", changed, err)
			}
			err = validateCompatibilityContentRoot(canonical, commit, pub.TargetCloudflare, identity, candidatePath)
			if (err != nil) != test.wantErr {
				t.Fatalf("validate content closure err=%v wantErr=%t", err, test.wantErr)
			}
		})
	}
}

func TestCompatibilityCarriedChannelRejectsEveryRouteMutationClass(t *testing.T) {
	identity := pub.CompatibilityState{ID: "infra-legacy", RouteRoot: "yum/infra/x86_64"}
	channel := pub.ChannelState{
		View: "latest", Repo: identity.ID, OS: "cross-el", Arch: "x86_64",
		RemoteKey:  path.Join(".sow/channels/latest", identity.ID, "cross-el/x86_64.json"),
		LegacyRoot: identity.RouteRoot, Generation: 4,
	}
	base := "https://repo.invalid/"
	if err := validateCompatibilityPlanRouteUnchanged(pub.Plan{CDNBaseURL: base}, identity, channel); err != nil {
		t.Fatalf("route-neutral carried plan was rejected: %v", err)
	}

	tests := []struct {
		name string
		plan pub.Plan
	}{
		{name: "raw-write", plan: pub.Plan{CDNBaseURL: base, Objects: []pub.PlannedObject{{RemoteKey: identity.RouteRoot + "/pkg.rpm"}}}},
		{name: "generation-write", plan: pub.Plan{CDNBaseURL: base, Objects: []pub.PlannedObject{{RemoteKey: ".sow/generations/00000000000000000005/yum/" + identity.RouteRoot + "/repodata/repomd.xml"}}}},
		{name: "channel-write", plan: pub.Plan{CDNBaseURL: base, Objects: []pub.PlannedObject{{RemoteKey: channel.RemoteKey}}}},
		{name: "mirror-write", plan: pub.Plan{CDNBaseURL: base, Objects: []pub.PlannedObject{{RemoteKey: "_sow/v1/mirrorlist/latest/infra-legacy/cross-el/x86_64.txt"}}}},
		{name: "trust-write", plan: pub.Plan{CDNBaseURL: base, Objects: []pub.PlannedObject{{RemoteKey: config.YUMCompatibilityRepositoryTrustRoute(identity.ID)}}}},
		{name: "delete", plan: pub.Plan{CDNBaseURL: base, Deletes: []pub.PlannedDelete{{RemoteKey: identity.RouteRoot + "/repodata/repomd.xml"}}}},
		{name: "trust-delete", plan: pub.Plan{CDNBaseURL: base, Deletes: []pub.PlannedDelete{{RemoteKey: config.YUMCompatibilityPackageTrustRoute(identity.ID)}}}},
		{name: "purge", plan: pub.Plan{CDNBaseURL: base, PurgeURLs: []string{base + "_sow/v1/mirrorlist/latest/infra-legacy/cross-el/x86_64.txt"}}},
		{name: "trust-purge", plan: pub.Plan{CDNBaseURL: base, PurgeURLs: []string{base + config.YUMCompatibilityRepositoryTrustRoute(identity.ID)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateCompatibilityPlanRouteUnchanged(test.plan, identity, channel); err == nil {
				t.Fatal("compatibility route mutation was accepted")
			}
		})
	}
}

func TestCompatibilityRollbackDeletesS3RoutesAndCandidateExtrasWithNegativeClosure(t *testing.T) {
	id := "infra-legacy-x86-64"
	identity := pub.CompatibilityState{ID: id, RouteRoot: "yum/infra/x86_64"}
	channel := pub.ChannelState{View: "latest", Repo: id, OS: "cross-el", Arch: "x86_64", Generation: 7}
	mirror := path.Join("_sow/v1/mirrorlist", "latest", id, "cross-el", "x86_64.txt")
	packageTrust := config.YUMCompatibilityPackageTrustRoute(id)
	repositoryTrust := config.YUMCompatibilityRepositoryTrustRoute(id)
	sha := strings.Repeat("a", 64)
	objects := []pub.PlannedObject{
		{RemoteKey: identity.RouteRoot + "/Packages/p/pkg.rpm", Class: pub.ObjectImmutable, Size: 1, SHA256: sha, CDNPath: identity.RouteRoot + "/Packages/p/pkg.rpm"},
		{RemoteKey: identity.RouteRoot + "/repodata/repomd.xml", Class: pub.ObjectYUMAliasPointer, Size: 2, SHA256: sha, CDNPath: identity.RouteRoot + "/repodata/repomd.xml"},
		{RemoteKey: ".sow/generations/00000000000000000007/yum/" + identity.RouteRoot + "/repodata/repomd.xml", Class: pub.ObjectMetadata, Size: 2, SHA256: sha, CDNPath: "_sow/v1/g/00000000000000000007/" + identity.RouteRoot + "/repodata/repomd.xml"},
		{RemoteKey: mirror, Class: pub.ObjectPointer, Size: 3, SHA256: sha, CDNPath: mirror},
		{RemoteKey: packageTrust, Class: pub.ObjectImmutable, Size: 4, SHA256: sha, CDNPath: packageTrust},
		{RemoteKey: repositoryTrust, Class: pub.ObjectImmutable, Size: 5, SHA256: sha, CDNPath: repositoryTrust},
	}
	rawRemoved := map[string]manifest.Entry{
		identity.RouteRoot + "/Packages/p/pkg.rpm": compatibilityTestManifestEntryWithSHA(identity.RouteRoot+"/Packages/p/pkg.rpm", 1, sha),
	}
	deletes, err := rolledBackCompatibilityRouteDeletes(id, identity, channel, objects, rawRemoved, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := (pub.Plan{Deletes: deletes}).WithCDN("https://repo.invalid/")
	if err != nil {
		t.Fatalf("close compatibility rollback plan: %v", err)
	}
	want := map[string]struct{}{mirror: {}, packageTrust: {}, repositoryTrust: {}, identity.RouteRoot + "/Packages/p/pkg.rpm": {}}
	if len(plan.Deletes) != len(want) || len(plan.VerifyAbsent) != len(want) || len(plan.PurgeURLs) != len(want) {
		t.Fatalf("rollback closure deletes=%#v absent=%#v purges=%#v", plan.Deletes, plan.VerifyAbsent, plan.PurgeURLs)
	}
	for _, deletion := range plan.Deletes {
		if deletion.Class != pub.DeleteCompatibilityServing {
			t.Fatalf("rollback deletion class=%s", deletion.Class)
		}
		if _, expected := want[deletion.RemoteKey]; !expected {
			t.Fatalf("rollback unexpectedly deletes preserved route %s", deletion.RemoteKey)
		}
		if strings.HasPrefix(deletion.RemoteKey, ".sow/generations/") {
			t.Fatalf("rollback deletes immutable generation route %s", deletion.RemoteKey)
		}
	}
	for key := range want {
		url := "https://repo.invalid/" + key
		found := false
		for _, absent := range plan.VerifyAbsent {
			found = found || absent.URL == url
		}
		if !found {
			t.Fatalf("rollback lacks negative verification for %s", key)
		}
	}

	for _, missing := range []string{mirror, packageTrust, repositoryTrust} {
		filtered := append([]pub.PlannedObject(nil), objects...)
		for index, object := range filtered {
			if object.RemoteKey == missing {
				filtered = append(filtered[:index:index], filtered[index+1:]...)
				break
			}
		}
		if _, err := rolledBackCompatibilityRouteDeletes(id, identity, channel, filtered, rawRemoved, nil); err == nil {
			t.Fatalf("rollback accepted missing evidence %s", missing)
		}
	}
}

func TestCompatibilityRollbackRemovesIndependentChannelVector(t *testing.T) {
	id := "infra-legacy-x86-64"
	channelKey := ".sow/channels/latest/" + id + "/cross-el/x86_64.json"
	identity := pub.CompatibilityState{ID: id, ChannelRemoteKey: channelKey}
	parent := &pub.TargetGeneration{Channels: []pub.ChannelState{{
		View: "latest", Repo: id, OS: "cross-el", Arch: "x86_64",
		RemoteKey: channelKey, LegacyRoot: "yum/infra/x86_64", Generation: 7,
	}}}
	prepared := preparedPublication{compatibilityRollbacks: map[string]pub.CompatibilityState{id: identity}}
	channels, err := desiredPublicationChannels(parent, prepared, 8, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(channels) != 0 {
		t.Fatalf("rolled-back compatibility channel survived desired vector: %#v", channels)
	}
}

func TestCompatibilityRollbackTamperedLocalParentMakesZeroProviderCalls(t *testing.T) {
	root := t.TempDir()
	cfg, err := config.Decode(strings.NewReader(publishAffinityBuildConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Root = root
	cfg.Path = filepath.Join(root, "sow.yaml")
	canonical := state.New(cfg.StatePath())
	tampered := filepath.Join(root, "tampered-generation.json")
	if err := os.WriteFile(tampered, []byte(`{"schema":"foreign"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{remoteStatePath("cf", "generation.json"): tampered}, "test: tampered local parent"); err != nil || !changed {
		t.Fatalf("install tampered parent changed=%t err=%v", changed, err)
	}
	selected := filepath.Join(root, "selected.tsv")
	writePublishManifest(t, selected, publishManifestEntry("affinity/cf/payload/tool", "asset"))
	prepared := preparedPublication{
		view: "latest", manifestPath: selected, scopes: []string{"affinity/cf"},
		projections: []publicationProjection{{
			view: "latest", repo: cfg.Repos[0], os: "all", arch: "all", sourceRoot: "affinity/cf",
			canonicalRoot: "affinity/cf", remoteRoot: "affinity/cf", legacyRoot: "affinity/cf",
		}},
	}
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	txDir := t.TempDir()
	if _, err := buildTargetPublication(t.Context(), cfg, canonical, cfg.Repos, prepared, "cf", plumbing.ZeroHash, txDir, commonFlags{workers: 1, chunk: 1}); err == nil || !strings.Contains(err.Error(), "decode local target cf generation") {
		t.Fatalf("tampered local rollback parent err=%v", err)
	}
	transport.mutex.Lock()
	remoteCalls := transport.puts + transport.copies + transport.deletes + transport.purges + transport.cdnGets + transport.listCalls + transport.objectGets + transport.headCalls
	transport.mutex.Unlock()
	if remoteCalls != 0 {
		t.Fatalf("tampered local rollback evidence reached provider calls=%d", remoteCalls)
	}
}

func TestRolledBackCompatibilityPlanRequiresExactPositiveAndNegativeClosure(t *testing.T) {
	id := "infra-legacy-x86-64"
	route := "yum/infra/x86_64"
	sha := strings.Repeat("a", 64)
	removed := route + "/Packages/p/pkg.rpm"
	mirror := "_sow/v1/mirrorlist/latest/" + id + "/cross-el/x86_64.txt"
	prepared := preparedPublication{
		projections: []publicationProjection{{
			repo: config.Repo{ID: "owner", Type: "yum"}, arch: "x86_64", sourceRoot: route,
			compatibilityID: id, compatibilityRollback: true,
		}},
		compatibilityRollbacks: map[string]pub.CompatibilityState{id: {ID: id, RouteRoot: route}},
	}
	plan := pub.Plan{Objects: []pub.PlannedObject{
		{SourcePath: route + "/repodata/legacy-primary.xml.gz", RemoteKey: route + "/repodata/legacy-primary.xml.gz", Size: 1, SHA256: sha, Class: pub.ObjectCompatibilityRollbackMetadata, CDNPath: route + "/repodata/legacy-primary.xml.gz"},
		{SourcePath: route + "/repodata/repomd.xml", RemoteKey: route + "/repodata/repomd.xml", Size: 2, SHA256: sha, Class: pub.ObjectCompatibilityRollbackPointer, CDNPath: route + "/repodata/repomd.xml"},
	}, Removed: []string{removed}, Deletes: []pub.PlannedDelete{
		{Class: pub.DeleteCompatibilityServing, SourcePath: removed, RemoteKey: removed, Size: 3, SHA256: sha, CDNPath: removed},
		{Class: pub.DeleteCompatibilityServing, SourcePath: mirror, RemoteKey: mirror, Size: 4, SHA256: sha, CDNPath: mirror},
		{Class: pub.DeleteCompatibilityServing, SourcePath: config.YUMCompatibilityPackageTrustRoute(id), RemoteKey: config.YUMCompatibilityPackageTrustRoute(id), Size: 5, SHA256: sha, CDNPath: config.YUMCompatibilityPackageTrustRoute(id)},
		{Class: pub.DeleteCompatibilityServing, SourcePath: config.YUMCompatibilityRepositoryTrustRoute(id), RemoteKey: config.YUMCompatibilityRepositoryTrustRoute(id), Size: 6, SHA256: sha, CDNPath: config.YUMCompatibilityRepositoryTrustRoute(id)},
	}}
	plan, err := plan.WithCDN("https://repo.invalid/base/")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRolledBackCompatibilityPublicationPlan(prepared, plan); err != nil {
		t.Fatalf("exact rollback closure rejected: %v", err)
	}
	withoutVerify := plan
	withoutVerify.Verify = withoutVerify.Verify[1:]
	if err := validateRolledBackCompatibilityPublicationPlan(prepared, withoutVerify); err == nil {
		t.Fatal("rollback closure without positive Verify passed")
	}
	withoutAbsent := plan
	withoutAbsent.VerifyAbsent = withoutAbsent.VerifyAbsent[1:]
	if err := validateRolledBackCompatibilityPublicationPlan(prepared, withoutAbsent); err == nil {
		t.Fatal("rollback closure without VerifyAbsent passed")
	}
	withoutPurge := plan
	withoutPurge.PurgeURLs = withoutPurge.PurgeURLs[1:]
	if err := validateRolledBackCompatibilityPublicationPlan(prepared, withoutPurge); err == nil {
		t.Fatal("rollback closure without purge passed")
	}
	unrelated := plan
	unrelatedKey := "yum/other/x86_64/Packages/o/other.rpm"
	unrelatedURL := "https://repo.invalid/base/" + unrelatedKey
	unrelated.Deletes = append(unrelated.Deletes, pub.PlannedDelete{
		Class: pub.DeleteCompatibilityServing, SourcePath: unrelatedKey, RemoteKey: unrelatedKey,
		Size: 7, SHA256: sha, CDNPath: unrelatedKey,
	})
	unrelated.VerifyAbsent = append(unrelated.VerifyAbsent, pub.VerifyAbsentObject{URL: unrelatedURL})
	unrelated.PurgeURLs = append(unrelated.PurgeURLs, unrelatedURL)
	if err := validateRolledBackCompatibilityPublicationPlan(prepared, unrelated); err == nil || !strings.Contains(err.Error(), "unrelated deletion") {
		t.Fatalf("rollback closure accepted unrelated compatibility deletion: %v", err)
	}
}

func TestCompatibilityPlanRouteRequiresExactObjectsVerifyAndPurge(t *testing.T) {
	canonical := state.New(filepath.Join(t.TempDir(), ".sow"))
	identity := pub.CompatibilityState{ID: "infra-legacy", RouteRoot: "yum/infra/x86_64", RepomdSHA256: strings.Repeat("d", 64)}
	entries := []manifest.Entry{
		compatibilityTestManifestEntry("Packages/p/pkg.rpm", "1"),
		compatibilityTestManifestEntry("pkg.rpm", "2"),
		compatibilityTestManifestEntry("repodata/"+strings.Repeat("a", 64)+"-filelists.xml.gz", "3"),
		compatibilityTestManifestEntry("repodata/"+strings.Repeat("b", 64)+"-other.xml.gz", "4"),
		compatibilityTestManifestEntry("repodata/"+strings.Repeat("c", 64)+"-primary.xml.gz", "5"),
		compatibilityTestManifestEntryWithSHA("repodata/repomd.xml", 6, identity.RepomdSHA256),
		compatibilityTestManifestEntry("repodata/repomd.xml.asc", "7"),
	}
	candidateFile := filepath.Join(t.TempDir(), "candidate.tsv")
	writeCompatibilityTestManifest(t, candidateFile, entries)
	candidateSHA, candidateGit, candidateSize, err := fileSHA256AndGitBlob(candidateFile)
	if err != nil {
		t.Fatal(err)
	}
	packageTrustFile := filepath.Join(t.TempDir(), "packages.pgp")
	repositoryTrustFile := filepath.Join(t.TempDir(), "repository.pgp")
	packageTrustBody := []byte("frozen package OpenPGP packets\n")
	repositoryTrustBody := []byte("frozen repository OpenPGP packets\n")
	if err := os.WriteFile(packageTrustFile, packageTrustBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repositoryTrustFile, repositoryTrustBody, 0o600); err != nil {
		t.Fatal(err)
	}
	packageSHA, packageGit, packageSize, err := fileSHA256AndGitBlob(packageTrustFile)
	if err != nil {
		t.Fatal(err)
	}
	repositorySHA, repositoryGit, repositorySize, err := fileSHA256AndGitBlob(repositoryTrustFile)
	if err != nil {
		t.Fatal(err)
	}
	identity.PackageTrustSHA256, identity.PackageTrustGit, identity.PackageTrustSize = packageSHA, packageGit.String(), packageSize
	identity.RepositoryKeySHA256 = repositoryTrustAnchorDigest(repositoryTrustBody)
	sourceRef, err := state.YUMCompatibilitySourceRef(identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	receipt := yumCompatibilityCandidate{
		Schema: yumCompatibilityCandidateSchema, ID: identity.ID, Root: identity.RouteRoot, Carrier: "carrier", OwnerRepo: "owner",
		SourceRef: sourceRef.String(), SourceCommit: strings.Repeat("1", 40),
		SourceManifestSHA256: strings.Repeat("1", 64), SourceManifestGit: strings.Repeat("1", 40), SourceManifestSize: 1,
		AdoptionSHA256: strings.Repeat("2", 64), AdoptionGit: strings.Repeat("2", 40), AdoptionSize: 1,
		PackageTrustSHA256: packageSHA, PackageTrustGit: packageGit.String(), PackageTrustSize: packageSize,
		CandidateManifestSHA256: candidateSHA, CandidateManifestGit: candidateGit.String(), CandidateManifestSize: candidateSize,
		RepomdSHA256: identity.RepomdSHA256, RepositoryKeySHA256: identity.RepositoryKeySHA256,
		RepositoryTrustSHA256: repositorySHA, RepositoryTrustGit: repositoryGit.String(), RepositoryTrustSize: repositorySize,
		Packages: 1, Bytes: 1,
	}
	receipt.FreezeConfirm, err = yumCompatibilityConfirmation("freeze", receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptBody, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptBody = append(receiptBody, '\n')
	receiptFile := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(receiptFile, receiptBody, 0o600); err != nil {
		t.Fatal(err)
	}
	candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(identity.ID)
	receiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(identity.ID)
	packagePath, _ := state.YUMCompatibilityPackageTrustPath(identity.ID)
	repositoryPath, _ := state.YUMCompatibilityRepositoryTrustPath(identity.ID)
	commit, changed, err := canonical.InstallPaths(map[string]string{
		candidatePath: candidateFile, receiptPath: receiptFile, packagePath: packageTrustFile, repositoryPath: repositoryTrustFile,
	}, "test: candidate and exact frozen trust")
	if err != nil || !changed {
		t.Fatalf("install candidate changed=%t err=%v", changed, err)
	}
	generation := pub.TargetGeneration{Target: pub.TargetCloudflare, Generation: 7}
	channel := pub.ChannelState{
		View: "latest", Repo: identity.ID, OS: "cross-el", Arch: "x86_64", Generation: generation.Generation,
		RemoteKey: ".sow/channels/latest/infra-legacy/cross-el/x86_64.json", LegacyRoot: identity.RouteRoot,
	}
	trust := []compatibilityFrozenTrustObject{
		{remotePath: config.YUMCompatibilityPackageTrustRoute(identity.ID), size: packageSize, sha256: packageSHA},
		{remotePath: config.YUMCompatibilityRepositoryTrustRoute(identity.ID), size: repositorySize, sha256: repositorySHA},
	}
	plan := compatibilityExactPlanFixture(t, entries, trust, identity, channel, generation.Generation)
	if err := validateCompatibilityPlanRoute(canonical, commit, generation, plan, identity, channel, candidatePath); err != nil {
		t.Fatalf("exact compatibility plan was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(pub.Plan) pub.Plan
	}{
		{name: "object-omission", mutate: func(plan pub.Plan) pub.Plan {
			for index, object := range plan.Objects {
				if object.RemoteKey == identity.RouteRoot+"/Packages/p/pkg.rpm" {
					plan.Objects = append(plan.Objects[:index:index], plan.Objects[index+1:]...)
					break
				}
			}
			return plan
		}},
		{name: "repository-trust-omission", mutate: func(plan pub.Plan) pub.Plan {
			for index, object := range plan.Objects {
				if object.RemoteKey == config.YUMCompatibilityRepositoryTrustRoute(identity.ID) {
					plan.Objects = append(plan.Objects[:index:index], plan.Objects[index+1:]...)
					break
				}
			}
			return plan
		}},
		{name: "verification-omission", mutate: func(plan pub.Plan) pub.Plan {
			plan.Verify = append([]pub.VerifyObject(nil), plan.Verify[1:]...)
			return plan
		}},
		{name: "purge-omission", mutate: func(plan pub.Plan) pub.Plan {
			plan.PurgeURLs = append([]string(nil), plan.PurgeURLs[1:]...)
			return plan
		}},
		{name: "route-delete", mutate: func(plan pub.Plan) pub.Plan {
			plan.Deletes = []pub.PlannedDelete{{RemoteKey: identity.RouteRoot + "/repodata/repomd.xml"}}
			return plan
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateCompatibilityPlanRoute(canonical, commit, generation, test.mutate(plan), identity, channel, candidatePath); err == nil {
				t.Fatal("incomplete compatibility route closure was accepted")
			}
		})
	}
}

func TestLoadFrozenCompatibilityPackageKeyringIgnoresMutableOwnerPath(t *testing.T) {
	root := t.TempDir()
	canonical := state.New(filepath.Join(root, ".sow"))
	trustFile := writeRPMPackageTrustFixture(t, root)
	trustBody, err := os.ReadFile(trustFile)
	if err != nil {
		t.Fatal(err)
	}
	trustPath, _ := state.YUMCompatibilityPackageTrustPath("infra-legacy")
	freezeCommit, changed, err := canonical.InstallPaths(map[string]string{trustPath: trustFile}, "test: freeze compatibility package trust")
	if err != nil || !changed {
		t.Fatalf("install trust changed=%t err=%v", changed, err)
	}
	blob, exists, err := canonical.BlobIdentityAt(freezeCommit, trustPath)
	if err != nil || !exists {
		t.Fatalf("read frozen trust blob exists=%t err=%v", exists, err)
	}
	identity := pub.CompatibilityState{
		ID: "infra-legacy", FreezeCommit: freezeCommit.String(), PackageTrustSHA256: digestBytesCLI(trustBody),
		PackageTrustGit: blob.Hash.String(), PackageTrustSize: blob.Size,
	}
	if keyring, err := loadFrozenCompatibilityPackageKeyring(canonical, identity); err != nil || keyring == nil {
		t.Fatalf("load frozen package trust keyring=%v err=%v", keyring, err)
	}

	// A later owner-keyring edit is irrelevant: the L4 compatibility verifier
	// resolves the exact preservation commit, not today's config path or HEAD.
	mutated := filepath.Join(root, "mutated-trust")
	if err := os.WriteFile(mutated, []byte("not a keyring\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{trustPath: mutated}, "test: mutate current package trust"); err != nil || !changed {
		t.Fatalf("mutate current trust changed=%t err=%v", changed, err)
	}
	if keyring, err := loadFrozenCompatibilityPackageKeyring(canonical, identity); err != nil || keyring == nil {
		t.Fatalf("frozen trust followed mutable HEAD: keyring=%v err=%v", keyring, err)
	}
	tampered := identity
	tampered.PackageTrustSHA256 = strings.Repeat("0", 64)
	if _, err := loadFrozenCompatibilityPackageKeyring(canonical, tampered); err == nil {
		t.Fatal("tampered frozen trust identity was accepted")
	}
}

func compatibilityTestManifestEntry(name, digit string) manifest.Entry {
	return compatibilityTestManifestEntryWithSHA(name, int64(len(name)), strings.Repeat(digit, 64))
}

func compatibilityTestManifestEntryWithSHA(name string, size int64, value string) manifest.Entry {
	digest, err := hex.DecodeString(value)
	if err != nil || len(digest) != 32 {
		panic("invalid test SHA-256")
	}
	var sha [32]byte
	copy(sha[:], digest)
	return manifest.Entry{Path: name, Size: size, SHA256: sha}
}

func writeCompatibilityTestManifest(t *testing.T, filename string, entries []manifest.Entry) {
	t.Helper()
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := manifest.WriteEntry(file, entry); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func compatibilityExactPlanFixture(t *testing.T, entries []manifest.Entry, trust []compatibilityFrozenTrustObject, identity pub.CompatibilityState, channel pub.ChannelState, generation uint64) pub.Plan {
	t.Helper()
	generationID := fmt.Sprintf("%020d", generation)
	plan := pub.Plan{Schema: "sow-publish-plan/v1"}
	for _, entry := range entries {
		remote := path.Join(identity.RouteRoot, entry.Path)
		if strings.HasPrefix(entry.Path, "repodata/") {
			generationKey := path.Join(".sow/generations", generationID, "yum", remote)
			plan.Objects = append(plan.Objects, pub.PlannedObject{
				SourcePath: remote, RemoteKey: generationKey, Size: entry.Size, SHA256: entry.HashString(), Class: pub.ObjectMetadata,
				CDNPath: path.Join("_sow/v1/g", generationID, remote),
			})
			class := pub.ObjectYUMAliasMetadata
			if entry.Path == "repodata/repomd.xml" || entry.Path == "repodata/repomd.xml.asc" {
				class = pub.ObjectYUMAliasPointer
			}
			plan.Objects = append(plan.Objects, pub.PlannedObject{SourcePath: remote, RemoteKey: remote, Size: entry.Size, SHA256: entry.HashString(), Class: class, CDNPath: remote})
			continue
		}
		plan.Objects = append(plan.Objects, pub.PlannedObject{SourcePath: remote, RemoteKey: remote, Size: entry.Size, SHA256: entry.HashString(), Class: pub.ObjectImmutable, CDNPath: remote})
	}
	for _, item := range trust {
		plan.Objects = append(plan.Objects, pub.PlannedObject{SourcePath: item.remotePath, RemoteKey: item.remotePath, Size: item.size, SHA256: item.sha256, Class: pub.ObjectImmutable, CDNPath: item.remotePath})
	}
	pointerKey, pointerBody, err := pub.YUMChannelPointer("https://repo.invalid/", channel)
	if err != nil {
		t.Fatal(err)
	}
	plan.Objects = append(plan.Objects, pub.PlannedObject{
		SourcePath: ".sow/generated/test-mirror.txt", RemoteKey: pointerKey, Size: int64(len(pointerBody)),
		SHA256: digestBytesCLI(pointerBody), Class: pub.ObjectPointer, CDNPath: pointerKey,
	})
	plan, err = plan.WithCDN("https://repo.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
