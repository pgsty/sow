package cli

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
)

func TestPublishTargetAffinitySelectionFailsBeforeRemoteWork(t *testing.T) {
	cf := config.Repo{ID: "cf-only", PublishTargets: []string{"cf"}}
	cos := config.Repo{ID: "cos-only", PublishTargets: []string{"cos"}}
	all := config.Repo{ID: "all"}
	for _, test := range []struct {
		name          string
		repos         []config.Repo
		targets       []string
		explicitRepos bool
		want          string
	}{
		{name: "default split can narrow", repos: []config.Repo{cf, cos}, targets: []string{"cf"}},
		{name: "omitted affinity means all", repos: []config.Repo{all}, targets: []string{"cf", "cos"}},
		{name: "target has no repo", repos: []config.Repo{cos}, targets: []string{"cf"}, want: "none of the selected"},
		{name: "explicit repo cannot be silently dropped", repos: []config.Repo{cf, cos}, targets: []string{"cf"}, explicitRepos: true, want: "cos-only publishes to none"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validatePublishTargetAffinitySelection(test.repos, test.targets, test.explicitRepos)
			if test.want == "" && err != nil {
				t.Fatal(err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("affinity error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestPublishCLIExplicitTargetAffinityMismatchFailsBeforeStateOrProvider(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAffinityBuildConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	var stdout, stderr bytes.Buffer
	code := Main([]string{"publish", "--view", "beta", "--target", "cf", "--repo", "cos-only", "--config", configPath}, &stdout, &stderr)
	if code != ExitConfig || !strings.Contains(stderr.String(), "cos-only publishes to none of the selected targets") {
		t.Fatalf("affinity mismatch code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".sow")); !os.IsNotExist(err) {
		t.Fatalf("affinity mismatch created canonical state before rejection: %v", err)
	}
	transport.mutex.Lock()
	remoteCalls := transport.puts + transport.copies + transport.deletes + transport.purges + transport.cdnGets + transport.listCalls + transport.objectGets + transport.headCalls
	transport.mutex.Unlock()
	if remoteCalls != 0 {
		t.Fatalf("affinity mismatch reached provider transport calls=%d", remoteCalls)
	}
}

func TestPublishCLIDefaultRepoSelectionFiltersSiblingTargetAffinity(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAffinityBuildConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_AFFINITY_CF_STORAGE", `{"access_key_id":"cf-access","secret_access_key":"cf-secret"}`)
	t.Setenv("SOW_AFFINITY_CF_CDN", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(arguments ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, repoID := range []string{"cf-only", "cos-only", "both"} {
		input := filepath.Join(inputs, repoID+".txt")
		if err := os.WriteFile(input, []byte(repoID+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", repoID, "--dest", "payload"); code != ExitOK {
			t.Fatalf("add %s code=%d stdout=%s stderr=%s", repoID, code, stdout, stderr)
		}
		if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", repoID); code != ExitOK {
			t.Fatalf("promote %s code=%d stdout=%s stderr=%s", repoID, code, stdout, stderr)
		}
	}
	code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(stdout, "target=cf view=latest") {
		t.Fatalf("default affinity publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	keys := make([]string, 0, len(transport.objects))
	for key := range transport.objects {
		keys = append(keys, key)
	}
	cosCount := len(transport.cosObjects)
	transport.mutex.Unlock()
	sort.Strings(keys)
	joined := strings.Join(keys, "\n")
	if !strings.Contains(joined, "affinity/cf/payload") || !strings.Contains(joined, "affinity/shared/payload") || strings.Contains(joined, "affinity/cos/") || cosCount != 0 {
		t.Fatalf("target affinity object set leaked sibling: cf=%v cos_count=%d", keys, cosCount)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	generation, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists {
		t.Fatalf("local cf generation exists=%v err=%v", exists, err)
	}
	var repoIDs []string
	for _, ref := range generation.Refs {
		repoID, err := publicationRefRepoID(ref.Name)
		if err != nil {
			t.Fatal(err)
		}
		repoIDs = append(repoIDs, repoID)
	}
	sort.Strings(repoIDs)
	if strings.Join(repoIDs, ",") != "both,cf-only" {
		t.Fatalf("default cf generation refs=%v", repoIDs)
	}
}

func TestPublishTargetViewAffinityRejectsEmptyTargetIntent(t *testing.T) {
	cfg := &config.Config{Views: map[string]config.View{
		"latest": {Repos: []string{"cos-only"}},
	}}
	repos := []config.Repo{
		{ID: "cf-only", PublishTargets: []string{"cf"}},
		{ID: "cos-only", PublishTargets: []string{"cos"}},
	}
	if err := validatePublishTargetViewAffinitySelection(cfg, repos, []string{"cf"}, []string{"latest"}); err == nil || !strings.Contains(err.Error(), "contains no selected repository") {
		t.Fatalf("empty target/view intent accepted: %v", err)
	}
	if err := validatePublishTargetViewAffinitySelection(cfg, repos, []string{"cos"}, []string{"latest"}); err != nil {
		t.Fatalf("matching target/view intent rejected: %v", err)
	}
}

func TestPreparedPublicationIsNarrowedPerTargetWithoutMutation(t *testing.T) {
	cf := config.Repo{ID: "cf-only", PublishTargets: []string{"cf"}}
	cos := config.Repo{ID: "cos-only", PublishTargets: []string{"cos"}}
	all := config.Repo{ID: "all", PublishTargets: []string{"cf", "cos"}}
	unionManifest := filepath.Join(t.TempDir(), "union.tsv")
	writeAffinityManifest(t, unionManifest, []manifest.Entry{
		affinityManifestEntry("asset/all/shared", "shared"),
		affinityManifestEntry("asset/cf/only", "cf"),
		affinityManifestEntry("asset/cos/only", "cos"),
	})
	prepared := preparedPublication{
		view: "latest", manifestPath: unionManifest,
		projections: []publicationProjection{
			{repo: cf, sourceRoot: "asset/cf"},
			{repo: cos, sourceRoot: "asset/cos"},
			{repo: all, sourceRoot: "asset/all"},
		},
		scopes:                        []string{"asset/cos", "asset/all", "asset/cf"},
		restoreRemovedProjectionRoots: map[string]bool{"asset/all": true, "asset/cf": true, "asset/cos": true},
	}
	narrowed, err := publicationPreparedForTarget(prepared, "cf", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(affinityRepoIDs([]config.Repo{narrowed.projections[0].repo, narrowed.projections[1].repo}), ","); got != "all,cf-only" {
		t.Fatalf("narrowed repos=%s", got)
	}
	if strings.Join(narrowed.scopes, ",") != "asset/all,asset/cf" || len(narrowed.restoreRemovedProjectionRoots) != 2 || !narrowed.restoreRemovedProjectionRoots["asset/all"] || !narrowed.restoreRemovedProjectionRoots["asset/cf"] {
		t.Fatalf("narrowed scopes=%v removed=%v", narrowed.scopes, narrowed.restoreRemovedProjectionRoots)
	}
	if narrowed.manifestPath == prepared.manifestPath || strings.Join(affinityManifestPaths(t, narrowed.manifestPath), ",") != "asset/all/shared,asset/cf/only" {
		t.Fatalf("CF target manifest=%s paths=%v", narrowed.manifestPath, affinityManifestPaths(t, narrowed.manifestPath))
	}
	cosNarrowed, err := publicationPreparedForTarget(prepared, "cos", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(affinityManifestPaths(t, cosNarrowed.manifestPath), ",") != "asset/all/shared,asset/cos/only" {
		t.Fatalf("COS target manifest=%s paths=%v", cosNarrowed.manifestPath, affinityManifestPaths(t, cosNarrowed.manifestPath))
	}
	if len(prepared.projections) != 3 || strings.Join(prepared.scopes, ",") != "asset/cos,asset/all,asset/cf" || len(prepared.restoreRemovedProjectionRoots) != 3 || prepared.manifestPath != unionManifest || strings.Join(affinityManifestPaths(t, prepared.manifestPath), ",") != "asset/all/shared,asset/cf/only,asset/cos/only" {
		t.Fatal("target narrowing mutated shared prepared publication")
	}
}

func TestPreparedPublicationWholeUnionReusesFrozenManifest(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, "selected-latest.tsv")
	writeAffinityManifest(t, manifestPath, []manifest.Entry{
		affinityManifestEntry("asset/all/payload", "shared"),
	})
	prepared := preparedPublication{
		view:         "latest",
		manifestPath: manifestPath,
		projections: []publicationProjection{{
			repo:       config.Repo{ID: "all"},
			sourceRoot: "asset/all",
		}},
		scopes: []string{"asset/all"},
	}
	for _, workspace := range []string{root, t.TempDir()} {
		narrowed, err := publicationPreparedForTarget(prepared, "cf", workspace)
		if err != nil {
			t.Fatal(err)
		}
		if narrowed.manifestPath != manifestPath {
			t.Fatalf("whole-union manifest copied to %s want immutable source %s", narrowed.manifestPath, manifestPath)
		}
	}
}

func TestPreparedPublicationWholeUnionStillRejectsOutOfScopeEntry(t *testing.T) {
	manifestPath := filepath.Join(t.TempDir(), "selected-latest.tsv")
	writeAffinityManifest(t, manifestPath, []manifest.Entry{
		affinityManifestEntry("asset/sibling/payload", "leak"),
	})
	prepared := preparedPublication{
		view:         "latest",
		manifestPath: manifestPath,
		projections: []publicationProjection{{
			repo:       config.Repo{ID: "all"},
			sourceRoot: "asset/all",
		}},
		scopes: []string{"asset/all"},
	}
	if _, err := publicationPreparedForTarget(prepared, "cf", t.TempDir()); err == nil || !strings.Contains(err.Error(), "outside union scopes") {
		t.Fatalf("whole-union shortcut accepted out-of-scope entry: %v", err)
	}
}

func TestBuildTargetPublicationFiltersAffinityThroughDesiredContentRefsAndPlan(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAffinityBuildConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_AFFINITY_CF_STORAGE", `{"access_key_id":"cf-access","secret_access_key":"cf-secret"}`)
	t.Setenv("SOW_AFFINITY_CF_CDN", `{"api_token":"cf-api-token"}`)
	t.Setenv("SOW_AFFINITY_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_AFFINITY_COS_CDN", `{"secret_id":"cos-id","secret_key":"cos-secret"}`)

	run := func(args ...string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := Main(args, &stdout, &stderr); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, repoID := range []string{"cf-only", "cos-only", "both"} {
		input := filepath.Join(inputs, repoID+".txt")
		if err := os.WriteFile(input, []byte(repoID+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		run("add", input, "--config", configPath, "--repo", repoID, "--dest", "payload")
		run("promote", "beta", "latest", "--config", configPath, "--repo", repoID)
	}

	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "publish-affinity-build-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(txDir) })
	values := commonFlags{workers: 2, chunk: 2}
	prepared, err := preparePublicationView(t.Context(), cfg, canonical, pool, cfg.Repos, "latest", txDir, values, nil, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	unionPath := prepared.manifestPath
	unionPaths := affinityManifestPaths(t, unionPath)
	if len(unionPaths) != 3 {
		t.Fatalf("prepared union paths=%v", unionPaths)
	}
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })

	rootByRepo := make(map[string]string)
	for _, projection := range prepared.projections {
		rootByRepo[projection.repo.ID] = projection.sourceRoot
	}
	for _, test := range []struct {
		target string
		want   []string
		deny   string
	}{
		{target: "cf", want: []string{"both", "cf-only"}, deny: "cos-only"},
		{target: "cos", want: []string{"both", "cos-only"}, deny: "cf-only"},
	} {
		t.Run(test.target, func(t *testing.T) {
			publication, err := buildTargetPublication(t.Context(), cfg, canonical, cfg.Repos, prepared, test.target, head, txDir, values)
			if err != nil {
				t.Fatal(err)
			}
			paths := affinityManifestPaths(t, publication.desiredManifest)
			assertAffinityPaths(t, paths, rootByRepo, test.want, test.deny)
			contentSHA, err := hashRegularPath(publication.desiredManifest)
			if err != nil || contentSHA != publication.request.Generation.ContentManifestSHA256 {
				t.Fatalf("target=%s content sha=%s generation=%s err=%v", test.target, contentSHA, publication.request.Generation.ContentManifestSHA256, err)
			}
			gotRefs := make([]string, 0, len(publication.request.Generation.Refs))
			for _, ref := range publication.request.Generation.Refs {
				repoID, err := publicationRefRepoID(ref.Name)
				if err != nil {
					t.Fatal(err)
				}
				gotRefs = append(gotRefs, repoID)
			}
			sort.Strings(gotRefs)
			if strings.Join(gotRefs, ",") != strings.Join(test.want, ",") {
				t.Fatalf("target=%s refs=%v want=%v", test.target, gotRefs, test.want)
			}
			planPaths := make([]string, 0, len(publication.request.Plan.Objects))
			for _, object := range publication.request.Plan.Objects {
				planPaths = append(planPaths, object.SourcePath)
			}
			assertAffinityPaths(t, planPaths, rootByRepo, test.want, test.deny)
			planBody, err := os.ReadFile(publication.planPath)
			if err != nil {
				t.Fatal(err)
			}
			persistedPlan, err := pub.DecodePlan(planBody)
			if err != nil {
				t.Fatal(err)
			}
			persistedPaths := make([]string, 0, len(persistedPlan.Objects))
			for _, object := range persistedPlan.Objects {
				persistedPaths = append(persistedPaths, object.SourcePath)
			}
			assertAffinityPaths(t, persistedPaths, rootByRepo, test.want, test.deny)
		})
	}
	if prepared.manifestPath != unionPath || len(prepared.projections) != 3 || strings.Join(affinityManifestPaths(t, unionPath), ",") != strings.Join(unionPaths, ",") {
		t.Fatal("per-target build mutated the shared prepared publication")
	}
}

func TestHistoricalTargetAffinityCannotSilentlyDropRefs(t *testing.T) {
	cf := config.Repo{ID: "cf-only", PublishTargets: []string{"cf"}}
	cos := config.Repo{ID: "cos-only", PublishTargets: []string{"cos"}}
	prepared := preparedPublication{
		view: "latest",
		projections: []publicationProjection{
			{repo: cf, sourceRoot: "asset/cf"},
			{repo: cos, sourceRoot: "asset/cos"},
		},
		refOverrides: map[string]pub.RefState{
			"refs/sow/views/latest/cos-only/all/all": {Name: "refs/sow/views/latest/cos-only/all/all"},
		},
	}
	if _, err := publicationPreparedForTarget(prepared, "cf", t.TempDir()); err == nil || !strings.Contains(err.Error(), "no longer publishes") {
		t.Fatalf("historical target-affinity narrowing accepted: %v", err)
	}
}

func TestPublishedTargetAffinityNarrowingRequiresExplicitReconciliation(t *testing.T) {
	cfg := &config.Config{Repos: []config.Repo{
		{ID: "cf-only", Type: "yum", Path: "yum/cf/{arch}", PublishTargets: []string{"cf"}, YUM: &config.YUMConfig{}},
		{ID: "cos-only", Type: "yum", Path: "yum/cos/{arch}", PublishTargets: []string{"cos"}, YUM: &config.YUMConfig{}},
	}}
	parent := &pub.TargetGeneration{Refs: []pub.RefState{{Name: "refs/sow/views/latest/cos-only/all/all"}}}
	if err := validatePublishedTargetAffinity(cfg, "cf", parent); err == nil || !strings.Contains(err.Error(), "explicit full target reconciliation") {
		t.Fatalf("stale target ref accepted: %v", err)
	}
	parent = &pub.TargetGeneration{Channels: []pub.ChannelState{{View: "latest", Repo: "cos-only", OS: "el9", Arch: "x86_64", RemoteKey: ".sow/channels/latest/cos-only/el9/x86_64.json"}}}
	if err := validatePublishedTargetAffinity(cfg, "cf", parent); err == nil || !strings.Contains(err.Error(), "affinity changed") {
		t.Fatalf("stale target channel accepted: %v", err)
	}
	parent = &pub.TargetGeneration{Refs: []pub.RefState{{Name: "refs/sow/views/latest/cf-only/all/all"}}}
	if err := validatePublishedTargetAffinity(cfg, "cf", parent); err != nil {
		t.Fatalf("matching target affinity rejected: %v", err)
	}
}

func TestYUMCompatibilityChannelInheritsSourceTargetAffinityAndRejectsUnknownID(t *testing.T) {
	projection := config.YUMCompatibilityProjection{
		ID: "infra-legacy-x86-64", Root: "yum/infra/x86_64", Mode: config.YUMCompatibilityModeFrozenCrossEL,
		Source: config.YUMCompatibilitySource{Repo: "infra-el9", View: "latest", OS: "cross-el", Arch: "x86_64", Commit: strings.Repeat("a", 40)},
	}
	cfg := &config.Config{
		Repos:                    []config.Repo{{ID: "infra-el9", Type: "yum", Path: "yum/infra/el9/{arch}", PublishTargets: []string{"cf"}, YUM: &config.YUMConfig{}}},
		CompatibilityProjections: []config.YUMCompatibilityProjection{projection},
	}
	channel := pub.ChannelState{
		View: "latest", Repo: projection.ID, OS: "cross-el", Arch: "x86_64", Generation: 1,
		RemoteKey: ".sow/channels/latest/infra-legacy-x86-64/cross-el/x86_64.json", LegacyRoot: projection.Root,
	}
	parent := &pub.TargetGeneration{Channels: []pub.ChannelState{channel}}
	if err := validatePublishedTargetAffinity(cfg, "cf", parent); err != nil {
		t.Fatalf("source-owned Cloudflare compatibility channel rejected: %v", err)
	}
	if err := validatePublishedTargetAffinity(cfg, "cos", parent); err == nil || !strings.Contains(err.Error(), "affinity changed") {
		t.Fatalf("compatibility channel escaped inherited affinity: %v", err)
	}
	parent.Channels[0].Repo = "removed-compatibility-id"
	parent.Channels[0].RemoteKey = ".sow/channels/latest/removed-compatibility-id/cross-el/x86_64.json"
	if err := validatePublishedTargetAffinity(cfg, "cf", parent); err == nil || !strings.Contains(err.Error(), "unknown repository or YUM compatibility projection") {
		t.Fatalf("unknown compatibility channel owner accepted: %v", err)
	}
}

func TestLocalPublishedTargetAffinityFailsBeforeProviderObservation(t *testing.T) {
	root := nginxWorkerTempDir(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	generation := pub.TargetGeneration{
		Schema: pub.TargetGenerationSchema, Target: pub.TargetCloudflare, Generation: 1,
		DesiredCommit: strings.Repeat("f", 40), IntentView: "latest",
		ConfigSHA256: strings.Repeat("a", 64), ContentManifestSHA256: strings.Repeat("b", 64),
		Refs: []pub.RefState{{
			Name: "refs/sow/views/latest/cos-only/all/all", Commit: strings.Repeat("c", 40), ManifestSHA256: strings.Repeat("d", 64),
		}},
	}
	body, err := generation.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(root, "generation.json")
	if err := os.WriteFile(filename, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{remoteStatePath("cf", "generation.json"): filename}, "target affinity fixture"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Repos: []config.Repo{{ID: "cos-only", PublishTargets: []string{"cos"}}}}
	if err := validateLocalPublishedTargetAffinity(canonical, cfg, []string{"cf"}); err == nil || !strings.Contains(err.Error(), "explicit full target reconciliation") {
		t.Fatalf("local affinity narrowing accepted: %v", err)
	}
}

func affinityManifestEntry(name, body string) manifest.Entry {
	return manifest.Entry{Path: name, Size: int64(len(body)), SHA256: sha256.Sum256([]byte(body))}
}

func writeAffinityManifest(t *testing.T, filename string, entries []manifest.Entry) {
	t.Helper()
	entries = append([]manifest.Entry(nil), entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	if err := writeExclusiveManifest(filename, func(destination io.Writer) error {
		for _, entry := range entries {
			if err := manifest.WriteEntry(destination, entry); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func affinityManifestPaths(t *testing.T, filename string) []string {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	var result []string
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return result
		}
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, entry.Path)
	}
}

func assertAffinityPaths(t *testing.T, paths []string, roots map[string]string, want []string, deny string) {
	t.Helper()
	allowed := make(map[string]struct{}, len(want))
	for _, repoID := range want {
		allowed[repoID] = struct{}{}
	}
	seen := make(map[string]bool, len(want))
	for _, filename := range paths {
		matched := ""
		for repoID, root := range roots {
			if filename == root || strings.HasPrefix(filename, strings.TrimSuffix(root, "/")+"/") {
				if matched != "" {
					t.Fatalf("path %s matches both %s and %s", filename, matched, repoID)
				}
				matched = repoID
			}
		}
		if matched == "" {
			t.Fatalf("path %s belongs to no prepared repository root", filename)
		}
		if matched == deny {
			t.Fatalf("path %s leaked denied repository %s", filename, deny)
		}
		if _, exists := allowed[matched]; !exists {
			t.Fatalf("path %s belongs to unexpected repository %s", filename, matched)
		}
		seen[matched] = true
	}
	for _, repoID := range want {
		if !seen[repoID] {
			t.Fatalf("repository %s has no desired/plan path in %v", repoID, paths)
		}
	}
}

const publishAffinityBuildConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: cf-only
    type: asset
    path: affinity/cf
    default_pool: public
    publish_targets: [cf]
    asset: {kind: release}
  - id: cos-only
    type: asset
    path: affinity/cos
    default_pool: public
    publish_targets: [cos]
    asset: {kind: release}
  - id: both
    type: asset
    path: affinity/shared
    default_pool: public
    publish_targets: [cf, cos]
    asset: {kind: release}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.test"}
  beta: {base_url: "https://beta.test"}
  stable: {base_url: "https://repo.test/pro/v1/basic"}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.test", bucket: repo-bucket, credential: env://SOW_AFFINITY_CF_STORAGE}
    cdn: {kind: cloudflare, base_url: "https://repo.test", beta_base_url: "https://beta.test", zone_id: zone-test, credential: env://SOW_AFFINITY_CF_CDN}
  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_AFFINITY_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_AFFINITY_COS_CDN}
edge:
  token_verifier: provider://test
`
