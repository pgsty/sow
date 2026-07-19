package config

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
)

const physicalMigrationLedgerSchema = "# schema=sow-physical-migration-ledger/v1"

type physicalTopologyRow struct {
	kind     string
	logical  string
	physical string
	scope    string
	bytes    string
	sha256   string
}

type physicalMigrationLedgerRow struct {
	kind        string
	owner       string
	source      string
	components  string
	disposition string
	lifecycle   string
	signer      string
	targets     string
}

func TestPigstyV1PhysicalMigrationContract(t *testing.T) {
	fixturePath := physicalMigrationFixturePath("SOW_PHYSICAL_MIGRATION_CONFIG", "../../docs/migration/fixtures/pigsty-v1.yaml")
	topologyPath := physicalMigrationFixturePath("SOW_PHYSICAL_MIGRATION_TOPOLOGY", "../../docs/migration/fixtures/legacy-physical-topology.tsv")
	ledgerPath := physicalMigrationFixturePath("SOW_PHYSICAL_MIGRATION_LEDGER", "../../docs/migration/fixtures/pigsty-v1-migration-ledger.tsv")

	fixture, err := os.Open(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Decode(fixture)
	closeErr := fixture.Close()
	if err != nil {
		t.Fatalf("decode complete physical migration fixture: %v", err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if len(cfg.Targets) != 0 || cfg.GPG.PrivateKey != "" || cfg.GPG.Passphrase != "" {
		t.Fatal("physical migration fixture must not contain a cloud target or signing secret")
	}
	if !strings.Contains(cfg.GPG.PublicKey, "unverified") {
		t.Fatalf("fixture public key path must remain an explicit non-claim: %q", cfg.GPG.PublicKey)
	}

	topology := readPhysicalTopologyFixture(t, topologyPath)
	ledger := readPhysicalMigrationLedger(t, ledgerPath)
	repos := make(map[string]Repo, len(cfg.Repos))
	configuredRepoIDs := make(map[string]bool, len(cfg.Repos))
	for _, repo := range cfg.Repos {
		repos[repo.ID] = repo
		configuredRepoIDs[repo.ID] = true
		if strings.HasPrefix(repo.Path, "selectors/") {
			t.Fatalf("synthetic selector path leaked into physical fixture: %s=%s", repo.ID, repo.Path)
		}
	}
	ledgerRepoIDs := make(map[string]bool, len(cfg.Repos))
	for _, row := range ledger {
		if row.owner != "-" {
			ledgerRepoIDs[row.owner] = true
		}
	}
	assertExactStringSet(t, "98-repo config/ledger ownership closure", ledgerRepoIDs, configuredRepoIDs)
	if len(configuredRepoIDs) != 98 || len(ledger) != 135 {
		t.Fatalf("physical migration identities repos=%d ledger_rows=%d want=98/135", len(configuredRepoIDs), len(ledger))
	}

	assertPhysicalAPTClosure(t, cfg, repos, topology, ledger)
	assertAPTInfraQuarantine(t, repos)
	assertPhysicalYUMClosure(t, cfg, repos, topology, ledger)
	assertPhysicalCompatibilityProjectionClosure(t, cfg, repos)
	assertPhysicalAssetClosure(t, cfg, repos, topology, ledger)
	assertProChecksumFixture(t, topology, "../../docs/migration/fixtures/pro-v4.4.0-checksums.sha256")
	assertPhysicalRepoGroups(t, cfg)
	assertQuarantinedCarrierUnitsZero(t, cfg)

	counts := countPhysicalTopologyKinds(topology)
	if counts["apt-index"] != 74 || counts["yum-repomd"] != 130 || counts["yum-repomd-nested"] != 1 ||
		counts["pro-file"] != 16 {
		t.Fatalf("canonical topology counts changed: apt=%d yum=%d nested=%d pro=%d",
			counts["apt-index"], counts["yum-repomd"], counts["yum-repomd-nested"], counts["pro-file"])
	}
	t.Logf("physical migration closure: apt_indices=%d yum_ordinary=%d yum_nested_quarantine=%d root_keys=7 prefixes=8 gated_pro=%d",
		counts["apt-index"], counts["yum-repomd"], counts["yum-repomd-nested"], counts["pro-file"])
	t.Log("trust boundary: lifecycle defaults remain policy-unverified; APT signatures are not in inventory; YUM metadata signatures are not-claimed and RPM signer bundles remain unverified")
}

func assertAPTInfraQuarantine(t *testing.T, repos map[string]Repo) {
	t.Helper()
	repo, exists := repos["apt-infra"]
	if !exists || repo.Type != "apt" {
		t.Fatal("apt-infra migration owner is absent")
	}
	want := []string{"pool/main/r/rustfs/rustfs_1.0.0-a94_*.deb", "stash/**"}
	got := append([]string(nil), repo.Exclude...)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("apt-infra quarantine changed: got=%v want=%v", got, want)
	}
}

func assertQuarantinedCarrierUnitsZero(t *testing.T, cfg *Config) {
	t.Helper()
	carrier, exists := cfg.RepoByName("yum-infra-legacy-compat")
	if !exists || carrier.IsActive() {
		t.Fatalf("YUM infra compatibility carrier must exist and remain inactive: %+v", carrier)
	}
	refUnits := 0
	if carrier.IsActive() {
		expanded, err := carrier.ExpandedPaths()
		if err != nil {
			t.Fatal(err)
		}
		refUnits = len(expanded)
	}
	viewUnits := 0
	for _, view := range cfg.Views {
		if carrier.IsActive() && (len(view.Repos) == 0 || containsString(view.Repos, carrier.ID)) {
			viewUnits++
		}
	}
	publishTargetUnits := 0
	for target := range cfg.Targets {
		if carrier.IsActive() && carrier.PublishesToTarget(target) {
			publishTargetUnits++
		}
	}
	upstreamUnits := 0
	for _, upstream := range cfg.Upstreams {
		if upstream.Repo == carrier.ID {
			upstreamUnits++
		}
	}
	if refUnits != 0 || viewUnits != 0 || publishTargetUnits != 0 || upstreamUnits != 0 {
		t.Fatalf("quarantined YUM infra carrier gained executable units: refs=%d views=%d publish_targets=%d upstreams=%d", refUnits, viewUnits, publishTargetUnits, upstreamUnits)
	}
	for _, id := range []string{"asset-legacy-bin-inventory"} {
		carrier, exists := cfg.RepoByName(id)
		if !exists || carrier.IsActive() || carrier.Asset == nil || !carrier.Asset.InventoryCarrier {
			t.Fatalf("asset inventory carrier must exist and remain inactive: %s=%+v", id, carrier)
		}
		for group, members := range cfg.RepoGroups {
			if containsString(members, id) {
				t.Fatalf("asset inventory carrier %s entered repo group %s", id, group)
			}
		}
		for _, upstream := range cfg.Upstreams {
			if upstream.Repo == id {
				t.Fatalf("asset inventory carrier %s gained upstream %s", id, upstream.ID)
			}
		}
	}
}

func physicalMigrationFixturePath(environment, fallback string) string {
	if override := os.Getenv(environment); override != "" {
		return override
	}
	return fallback
}

func readPhysicalTopologyFixture(t *testing.T, filename string) []physicalTopologyRow {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var result []physicalTopologyRow
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) != 6 {
			t.Fatalf("%s:%d: topology row has %d fields, want 6", filename, line, len(fields))
		}
		result = append(result, physicalTopologyRow{
			kind: fields[0], logical: fields[1], physical: fields[2], scope: fields[3], bytes: fields[4], sha256: fields[5],
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func readPhysicalMigrationLedger(t *testing.T, filename string) []physicalMigrationLedgerRow {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var result []physicalMigrationLedgerRow
	seen := make(map[string]bool)
	schemaSeen := false
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if text == physicalMigrationLedgerSchema {
			if schemaSeen {
				t.Fatalf("%s:%d: duplicate schema header", filename, line)
			}
			schemaSeen = true
			continue
		}
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) != 8 {
			t.Fatalf("%s:%d: ledger row has %d fields, want 8", filename, line, len(fields))
		}
		row := physicalMigrationLedgerRow{
			kind: fields[0], owner: fields[1], source: fields[2], components: fields[3],
			disposition: fields[4], lifecycle: fields[5], signer: fields[6], targets: fields[7],
		}
		key := row.kind + "\x00" + row.owner + "\x00" + row.source
		if seen[key] {
			t.Fatalf("%s:%d: duplicate ledger identity %q", filename, line, key)
		}
		seen[key] = true
		assertClosedPhysicalLedgerRow(t, filename, line, row)
		result = append(result, row)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !schemaSeen {
		t.Fatalf("%s: missing %s", filename, physicalMigrationLedgerSchema)
	}
	return result
}

func assertClosedPhysicalLedgerRow(t *testing.T, filename string, line int, row physicalMigrationLedgerRow) {
	t.Helper()
	allowedKinds := setOf("apt-suite", "yum-repo", "yum-policy-owner", "yum-nested", "inventory-carrier", "root-key", "root-prefix", "pro-file")
	allowedDispositions := setOf("mapped-review-required", "mapped-separate-noarch-review-required", "compatibility-projection-declared", "compatibility-policy-owner", "quarantine-overlap", "baseline-only", "external-builder-convergence", "gated-rebase-review-required", "excluded-empty-source+canonical-checksum-add", "adopted-latest-local-cutover-pending", "adopted-stable-local-cutover-pending")
	allowedLifecycle := setOf("active-policy-unverified", "frozen-policy-unverified", "cross-el-unresolved", "lifecycle-unresolved", "stable-gated-policy-unverified", "stable-gated-policy-verified", "not-applicable")
	allowedSigners := setOf("release-signature-not-inventory", "metadata-not-claimed+payload-keyring-unverified", "payload-keyring-unverified", "content-not-read", "not-applicable", "source-sha256-pinned", "source-pair+generated-sha256-pinned", "source-zero-byte+generated-sha256-verified", "sha256+gzip+tar-verified")
	allowedTargets := setOf("cf,cos", "cos", "none")
	checks := []struct {
		field string
		value string
		set   map[string]bool
	}{
		{"kind", row.kind, allowedKinds},
		{"disposition", row.disposition, allowedDispositions},
		{"lifecycle_evidence", row.lifecycle, allowedLifecycle},
		{"signer_evidence", row.signer, allowedSigners},
		{"targets", row.targets, allowedTargets},
	}
	for _, check := range checks {
		if !check.set[check.value] {
			t.Fatalf("%s:%d: unknown %s %q", filename, line, check.field, check.value)
		}
	}
	if strings.Contains(row.lifecycle, "verified") && !strings.Contains(row.lifecycle, "unverified") && row.kind != "pro-file" {
		t.Fatalf("%s:%d: ledger may not claim verified lifecycle evidence", filename, line)
	}
	if strings.Contains(row.signer, "verified") && !strings.Contains(row.signer, "unverified") && row.kind != "pro-file" {
		t.Fatalf("%s:%d: ledger may not claim verified signer evidence", filename, line)
	}
}

func assertPhysicalAPTClosure(t *testing.T, cfg *Config, repos map[string]Repo, topology []physicalTopologyRow, ledger []physicalMigrationLedgerRow) {
	t.Helper()
	want := topologyLogicalSet(topology, "apt-index")
	got := make(map[string]bool)
	seenSuites := make(map[string]bool)
	rows := 0
	for _, row := range ledger {
		if row.kind != "apt-suite" {
			continue
		}
		rows++
		repo, exists := repos[row.owner]
		if !exists || repo.Type != "apt" || repo.APT == nil {
			t.Fatalf("APT ledger owner is not an APT repo: %s", row.owner)
		}
		if !containsString(repo.APT.Suites, row.source) {
			t.Fatalf("APT ledger suite %s is not owned by %s", row.source, row.owner)
		}
		components := strings.Split(row.components, ",")
		sort.Strings(components)
		configured := repo.APT.ComponentsForSuite(row.source)
		sort.Strings(configured)
		if strings.Join(components, ",") != strings.Join(configured, ",") {
			t.Fatalf("APT component contract %s/%s ledger=%v config=%v", row.owner, row.source, components, configured)
		}
		if row.lifecycle != repo.LifecycleForSuite(row.source)+"-policy-unverified" || row.signer != "release-signature-not-inventory" || row.disposition != "mapped-review-required" || row.targets != "cf,cos" {
			t.Fatalf("APT evidence boundary changed for %s/%s: %+v", row.owner, row.source, row)
		}
		assertRepoTargetAffinity(t, repo, row.targets)
		identity := row.owner + "\x00" + row.source
		if seenSuites[identity] {
			t.Fatalf("APT suite appears twice in ledger: %s/%s", row.owner, row.source)
		}
		seenSuites[identity] = true
		for _, component := range configured {
			for _, arch := range repo.Arches {
				leaf := path.Join(repo.Path, "dists", row.source, component, "binary-"+arch)
				if got[leaf] {
					t.Fatalf("APT config expands duplicate index leaf %s", leaf)
				}
				got[leaf] = true
			}
		}
	}
	if rows != 27 {
		t.Fatalf("APT suite ledger rows=%d want=27", rows)
	}
	for _, repo := range cfg.Repos {
		if repo.Type != "apt" {
			continue
		}
		for _, suite := range repo.APT.Suites {
			if !seenSuites[repo.ID+"\x00"+suite] {
				t.Fatalf("APT repo/suite has no ledger disposition: %s/%s", repo.ID, suite)
			}
		}
	}
	assertExactStringSet(t, "APT physical index closure", got, want)
	if len(got) != 74 {
		t.Fatalf("APT expanded indices=%d want=74", len(got))
	}
}

func assertPhysicalYUMClosure(t *testing.T, cfg *Config, repos map[string]Repo, topology []physicalTopologyRow, ledger []physicalMigrationLedgerRow) {
	t.Helper()
	want := topologyLogicalSet(topology, "yum-repomd")
	got := make(map[string]bool)
	seenRepos := make(map[string]bool)
	rows := 0
	policyRows := 0
	nestedRows := 0
	for _, row := range ledger {
		switch row.kind {
		case "yum-repo":
			rows++
			repo, exists := repos[row.owner]
			if !exists || repo.Type != "yum" || repo.YUM == nil {
				t.Fatalf("YUM ledger owner is not a YUM repo: %s", row.owner)
			}
			if seenRepos[row.owner] {
				t.Fatalf("YUM repo appears twice in ledger: %s", row.owner)
			}
			seenRepos[row.owner] = true
			if row.source != repo.Path || row.components != "-" || row.signer != "metadata-not-claimed+payload-keyring-unverified" {
				t.Fatalf("YUM source/trust contract changed for %s: %+v config_path=%s", row.owner, row, repo.Path)
			}
			if repo.ID == "yum-infra-legacy-compat" {
				if repo.IsActive() || row.disposition != "compatibility-projection-declared" || row.lifecycle != "frozen-policy-unverified" || row.targets != "none" {
					t.Fatalf("YUM infra compatibility carrier contract drifted: repo=%+v ledger=%+v", repo, row)
				}
				for group, members := range cfg.RepoGroups {
					if containsString(members, repo.ID) {
						t.Fatalf("quarantined YUM infra carrier entered repo group %s", group)
					}
				}
			} else {
				wantDisposition := "mapped-review-required"
				if strings.HasPrefix(repo.ID, "yum-percona-") {
					wantDisposition = "mapped-separate-noarch-review-required"
					if repo.YUM.NoarchMode != YUMNoarchSeparate || !containsString(repo.Arches, "noarch") {
						t.Fatalf("Percona noarch leaf is not separately indexed: %+v", repo)
					}
				} else if repo.YUM.NoarchMode != YUMNoarchReplicate {
					t.Fatalf("non-Percona YUM repo changed noarch policy: %s=%s", repo.ID, repo.YUM.NoarchMode)
				}
				if row.disposition != wantDisposition || row.lifecycle != repo.OS.Lifecycle+"-policy-unverified" || row.targets != "cf,cos" {
					t.Fatalf("YUM evidence boundary changed for %s: %+v", repo.ID, row)
				}
				assertRepoTargetAffinity(t, repo, row.targets)
			}
			expanded, err := repo.ExpandedPaths()
			if err != nil {
				t.Fatalf("expand YUM repo %s: %v", repo.ID, err)
			}
			for _, leaf := range expanded {
				if got[leaf] {
					t.Fatalf("YUM config expands duplicate ordinary leaf %s", leaf)
				}
				got[leaf] = true
			}
		case "yum-policy-owner":
			policyRows++
			repo, exists := repos[row.owner]
			if !exists || repo.ID != "yum-infra-policy-el9" || repo.Type != "yum" || repo.YUM == nil || !repo.IsActive() {
				t.Fatalf("compatibility policy owner is missing or inactive: %+v", repo)
			}
			if seenRepos[row.owner] {
				t.Fatalf("YUM repo appears twice in ledger: %s", row.owner)
			}
			seenRepos[row.owner] = true
			if row.source != "-" || row.components != "-" || row.disposition != "compatibility-policy-owner" ||
				row.lifecycle != "active-policy-unverified" || row.signer != "payload-keyring-unverified" || row.targets != "cf,cos" ||
				repo.Path != "yum/infra/el9/{arch}" || repo.OS.Family != "el" || repo.OS.Major != 9 || repo.OS.Lifecycle != "active" ||
				repo.YUM.Compression != "zstd" || strings.Join(repo.Arches, ",") != "aarch64,x86_64" {
				t.Fatalf("compatibility policy owner contract changed: repo=%+v ledger=%+v", repo, row)
			}
			assertRepoTargetAffinity(t, repo, row.targets)
		case "yum-nested":
			nestedRows++
			if row.owner != "-" || row.source != "yum/pgdg/17/redhat/rhel-10-aarch64/rhel-10.0-aarch64" || row.disposition != "quarantine-overlap" || row.lifecycle != "lifecycle-unresolved" || row.targets != "none" {
				t.Fatalf("nested PGDG quarantine contract changed: %+v", row)
			}
			if _, exists := repoByExpandedPath(cfg, row.source); exists {
				t.Fatalf("nested PGDG child was incorrectly configured as a repo: %s", row.source)
			}
		}
	}
	if rows != 74 || policyRows != 1 || nestedRows != 1 {
		t.Fatalf("YUM ledger rows ordinary=%d policy=%d nested=%d want=74/1/1", rows, policyRows, nestedRows)
	}
	for _, repo := range cfg.Repos {
		if repo.Type == "yum" && !seenRepos[repo.ID] {
			t.Fatalf("YUM repo has no migration disposition: %s", repo.ID)
		}
	}
	assertExactStringSet(t, "YUM ordinary leaf closure", got, want)
	if len(got) != 130 {
		t.Fatalf("YUM expanded ordinary leaves=%d want=130", len(got))
	}
	nested := topologyLogicalSet(topology, "yum-repomd-nested")
	if len(nested) != 1 || !nested["yum/pgdg/17/redhat/rhel-10-aarch64/rhel-10.0-aarch64"] {
		t.Fatalf("nested PGDG physical inventory changed: %v", sortedSet(nested))
	}
	parent, exists := repos["yum-pgdg-17-el10"]
	if !exists || !containsString(parent.Exclude, "rhel-10.0-aarch64/**") {
		t.Fatalf("PGDG parent no longer excludes quarantined nested child: %+v", parent)
	}
}

func assertPhysicalCompatibilityProjectionClosure(t *testing.T, cfg *Config, repos map[string]Repo) {
	t.Helper()
	want := map[string]struct {
		root string
		arch string
	}{
		"infra-legacy-aarch64": {root: "yum/infra/aarch64", arch: "aarch64"},
		"infra-legacy-x86-64":  {root: "yum/infra/x86_64", arch: "x86_64"},
	}
	if len(cfg.CompatibilityProjections) != len(want) {
		t.Fatalf("physical compatibility projections=%d want=%d", len(cfg.CompatibilityProjections), len(want))
	}
	seen := make(map[string]bool, len(want))
	for _, projection := range cfg.CompatibilityProjections {
		expected, exists := want[projection.ID]
		if !exists || seen[projection.ID] {
			t.Fatalf("unknown or duplicate physical compatibility projection %+v", projection)
		}
		seen[projection.ID] = true
		if projection.Root != expected.root || projection.Mode != YUMCompatibilityModeFrozenCrossEL ||
			projection.Carrier != "yum-infra-legacy-compat" || projection.Source.Repo != "yum-infra-policy-el9" ||
			projection.Source.View != "latest" || projection.Source.OS != "cross-el" ||
			projection.Source.Arch != expected.arch || projection.Source.Commit != YUMCompatibilityPinAtFirstFreeze {
			t.Fatalf("physical compatibility projection changed: %+v", projection)
		}
	}
	carrier := repos["yum-infra-legacy-compat"]
	owner := repos["yum-infra-policy-el9"]
	if carrier.IsActive() || owner.Type != "yum" || !owner.IsActive() || owner.YUM == nil || owner.YUM.Compression != "zstd" {
		t.Fatalf("compatibility carrier/policy separation changed: carrier=%+v owner=%+v", carrier, owner)
	}
}

func assertPhysicalAssetClosure(t *testing.T, cfg *Config, repos map[string]Repo, topology []physicalTopologyRow, ledger []physicalMigrationLedgerRow) {
	t.Helper()
	rootScopes := topologyLogicalScopes(topology, "root-key-source")
	prefixScopes := topologyLogicalScopes(topology, "root-prefix-source")
	proSources := make(map[string]bool)
	proChecksumRows := 0
	for _, row := range topology {
		if row.kind == "pro-file" {
			if proSources[row.physical] {
				t.Fatalf("duplicate gated Pro topology source %s", row.physical)
			}
			proSources[row.physical] = true
			if row.physical == "pro/checksums" {
				proChecksumRows++
				if row.logical != "/pro/checksums" || row.scope != "gated-metadata-only" || row.bytes != "0" || row.sha256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
					t.Fatalf("legacy Pro checksum must remain the exact zero-byte, metadata-only inventory row: %+v", row)
				}
			}
		}
	}
	if proChecksumRows != 1 {
		t.Fatalf("legacy Pro checksum topology rows=%d want=1", proChecksumRows)
	}
	seenRoots := make(map[string]bool)
	seenPrefixes := make(map[string]bool)
	seenPro := make(map[string]bool)
	for _, row := range ledger {
		switch row.kind {
		case "inventory-carrier":
			repo := requireAssetRepo(t, repos, row.owner)
			if repo.IsActive() || !repo.Asset.InventoryCarrier || repo.Path != row.source || row.components != "-" || row.disposition != "baseline-only" || row.signer != "content-not-read" || row.targets != "none" {
				t.Fatalf("asset inventory carrier contract changed: %+v repo=%+v", row, repo)
			}
		case "root-key":
			repo := requireAssetRepo(t, repos, row.owner)
			cosOnly := repo.ID == "asset-root-cos"
			if !repo.IsActive() || repo.AssetPublicRoot() != "." || !containsString(repo.Asset.RootKeys, row.source) {
				t.Fatalf("root key %s is not exactly owned by %s", row.source, row.owner)
			}
			if row.components != "-" || row.lifecycle != "not-applicable" {
				t.Fatalf("root key carries invalid evidence fields: %+v", row)
			}
			if cosOnly {
				if row.disposition != "adopted-latest-local-cutover-pending" || row.signer != "source-sha256-pinned" || !containsString([]string{"cc", "claude", "ray"}, row.source) {
					t.Fatalf("COS-only root key local adoption evidence changed: %+v", row)
				}
			} else if row.disposition != "adopted-latest-local-cutover-pending" || row.signer != "source-pair+generated-sha256-pinned" || !containsString([]string{"beta", "get", "pig", "pkg"}, row.source) {
				t.Fatalf("shared root key canonical builder evidence changed: %+v", row)
			}
			wantTargets := scopesToTargets(rootScopes["/"+row.source])
			if row.targets != wantTargets {
				t.Fatalf("root key target affinity %s ledger=%s topology=%s", row.source, row.targets, wantTargets)
			}
			assertRepoTargetAffinity(t, repo, row.targets)
			seenRoots[row.source] = true
		case "root-prefix":
			repo := requireAssetRepo(t, repos, row.owner)
			if repo.AssetPublicRoot() != row.source || row.components != "-" || row.lifecycle != "not-applicable" || row.signer != "not-applicable" {
				t.Fatalf("root prefix contract changed: %+v repo=%+v", row, repo)
			}
			wantTargets := scopesToTargets(prefixScopes["/"+row.source+"/"])
			if row.targets != wantTargets {
				t.Fatalf("root prefix target affinity %s ledger=%s topology=%s", row.source, row.targets, wantTargets)
			}
			assertRepoTargetAffinity(t, repo, row.targets)
			seenPrefixes[row.source] = true
		case "pro-file":
			repo := requireAssetRepo(t, repos, row.owner)
			if !repo.IsActive() || repo.Path != "pro" || !containsString(repo.Exclude, "checksums") || repo.DefaultPool != "gated" || repo.AssetPublicRoot() != "gated/pro" || row.lifecycle != "stable-gated-policy-verified" || row.targets != "cf,cos" {
				t.Fatalf("gated pro migration contract changed: %+v repo=%+v", row, repo)
			}
			if !strings.HasPrefix(row.source, "pro/") {
				t.Fatalf("gated pro source is outside pro/: %s", row.source)
			}
			if row.source == "pro/checksums" {
				if row.disposition != "excluded-empty-source+canonical-checksum-add" || row.signer != "source-zero-byte+generated-sha256-verified" {
					t.Fatalf("gated Pro checksum replacement contract changed: %+v", row)
				}
			} else if row.disposition != "adopted-stable-local-cutover-pending" || row.signer != "sha256+gzip+tar-verified" {
				t.Fatalf("gated Pro archive evidence contract changed: %+v", row)
			}
			assertRepoTargetAffinity(t, repo, row.targets)
			seenPro[row.source] = true
		}
	}
	assertExactStringSet(t, "root exact key closure", seenRoots, stripTopologyRouteSet(rootScopes, "/", ""))
	assertExactStringSet(t, "root prefix closure", seenPrefixes, stripTopologyRouteSet(prefixScopes, "/", "/"))
	assertExactStringSet(t, "gated pro file closure", seenPro, proSources)
	if len(seenRoots) != 7 || len(seenPrefixes) != 8 || len(seenPro) != 16 {
		t.Fatalf("asset migration counts root=%d prefix=%d pro=%d want=7/8/16", len(seenRoots), len(seenPrefixes), len(seenPro))
	}
	if len(cfg.Repos) != 98 {
		t.Fatalf("complete physical migration repositories=%d want=98", len(cfg.Repos))
	}
}

func assertProChecksumFixture(t *testing.T, topology []physicalTopologyRow, fixturePath string) {
	t.Helper()
	body, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if got, want := hex.EncodeToString(sum[:]), "cc58dd54ee561c16b1a9728a5d45225690552e600cab0b9ab7122e81413c2fe9"; got != want {
		t.Fatalf("reviewed Pro checksum fixture digest=%s want=%s", got, want)
	}
	want := make(map[string]bool)
	for _, row := range topology {
		if row.kind == "pro-file" && row.physical != "pro/checksums" {
			want[row.physical] = true
		}
	}
	got := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || len(fields[0]) != 64 || fields[0] != strings.ToLower(fields[0]) {
			t.Fatalf("invalid Pro checksum fixture line %q", scanner.Text())
		}
		decoded, err := hex.DecodeString(fields[0])
		if err != nil || len(decoded) != sha256.Size {
			t.Fatalf("invalid Pro checksum digest %q: %v", fields[0], err)
		}
		name := path.Join("pro", fields[1])
		if got[name] {
			t.Fatalf("duplicate Pro checksum fixture path %s", name)
		}
		got[name] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	assertExactStringSet(t, "reviewed Pro checksum closure", got, want)
}

func assertPhysicalRepoGroups(t *testing.T, cfg *Config) {
	t.Helper()
	apt := make(map[string]bool)
	yumActive := make(map[string]bool)
	assetPublic := make(map[string]bool)
	assetGated := make(map[string]bool)
	for _, repo := range cfg.Repos {
		switch repo.Type {
		case "apt":
			apt[repo.ID] = true
		case "yum":
			if repo.IsActive() && repo.ID != "yum-infra-policy-el9" {
				yumActive[repo.ID] = true
			}
		case "asset":
			if repo.Asset != nil && repo.Asset.InventoryCarrier {
				continue
			}
			if repo.DefaultPool == "gated" {
				assetGated[repo.ID] = true
			} else {
				assetPublic[repo.ID] = true
			}
		}
	}
	assertExactStringSet(t, "apt-all repo group", sliceSet(cfg.RepoGroups["apt-all"]), apt)
	assertExactStringSet(t, "asset-public repo group", sliceSet(cfg.RepoGroups["asset-public"]), assetPublic)
	assertExactStringSet(t, "asset-gated repo group", sliceSet(cfg.RepoGroups["asset-gated"]), assetGated)
	yumUnion := make(map[string]bool)
	for _, group := range []string{"yum-gpsql", "yum-mssql", "yum-percona", "yum-pgdg", "yum-pgsql"} {
		members, exists := cfg.RepoGroups[group]
		if !exists || len(members) == 0 {
			t.Fatalf("missing exact YUM repo group %s", group)
		}
		for _, member := range members {
			if yumUnion[member] {
				t.Fatalf("YUM repo %s appears in multiple family groups", member)
			}
			yumUnion[member] = true
		}
	}
	assertExactStringSet(t, "active YUM family group partition", yumUnion, yumActive)
	for group, members := range cfg.RepoGroups {
		for _, forbidden := range []string{"yum-infra-legacy-compat", "yum-infra-policy-el9"} {
			if containsString(members, forbidden) {
				t.Fatalf("compatibility-only YUM repo %s entered repo group %s", forbidden, group)
			}
		}
	}
}

func requireAssetRepo(t *testing.T, repos map[string]Repo, id string) Repo {
	t.Helper()
	repo, exists := repos[id]
	if !exists || repo.Type != "asset" || repo.Asset == nil {
		t.Fatalf("ledger owner is not an asset repo: %s", id)
	}
	return repo
}

func assertRepoTargetAffinity(t *testing.T, repo Repo, targets string) {
	t.Helper()
	want := strings.Split(targets, ",")
	got := append([]string(nil), repo.PublishTargets...)
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("target affinity %s config=%v ledger=%v", repo.ID, got, want)
	}
}

func repoByExpandedPath(cfg *Config, wanted string) (Repo, bool) {
	for _, repo := range cfg.Repos {
		expanded, err := repo.ExpandedPaths()
		if err != nil {
			continue
		}
		for _, candidate := range expanded {
			if candidate == wanted {
				return repo, true
			}
		}
	}
	return Repo{}, false
}

func topologyLogicalSet(rows []physicalTopologyRow, kind string) map[string]bool {
	result := make(map[string]bool)
	for _, row := range rows {
		if row.kind == kind {
			if result[row.logical] {
				panic("duplicate topology logical identity: " + kind + "/" + row.logical)
			}
			result[row.logical] = true
		}
	}
	return result
}

func topologyLogicalScopes(rows []physicalTopologyRow, kind string) map[string]map[string]bool {
	result := make(map[string]map[string]bool)
	for _, row := range rows {
		if row.kind != kind {
			continue
		}
		if result[row.logical] == nil {
			result[row.logical] = make(map[string]bool)
		}
		result[row.logical][row.scope] = true
	}
	return result
}

func scopesToTargets(scopes map[string]bool) string {
	var targets []string
	if scopes["cf"] {
		targets = append(targets, "cf")
	}
	if scopes["co"] {
		targets = append(targets, "cos")
	}
	return strings.Join(targets, ",")
}

func stripTopologyRouteSet(scopes map[string]map[string]bool, prefix, suffix string) map[string]bool {
	result := make(map[string]bool, len(scopes))
	for value := range scopes {
		value = strings.TrimPrefix(value, prefix)
		value = strings.TrimSuffix(value, suffix)
		result[value] = true
	}
	return result
}

func countPhysicalTopologyKinds(rows []physicalTopologyRow) map[string]int {
	result := make(map[string]int)
	for _, row := range rows {
		result[row.kind]++
	}
	return result
}

func assertExactStringSet(t *testing.T, label string, got, want map[string]bool) {
	t.Helper()
	var gotOnly, wantOnly []string
	for value := range got {
		if !want[value] {
			gotOnly = append(gotOnly, value)
		}
	}
	for value := range want {
		if !got[value] {
			wantOnly = append(wantOnly, value)
		}
	}
	sort.Strings(gotOnly)
	sort.Strings(wantOnly)
	if len(gotOnly) > 0 || len(wantOnly) > 0 {
		t.Fatalf("%s differs: config/ledger-only=%v topology-only=%v", label, gotOnly, wantOnly)
	}
}

func sortedSet(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sliceSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func setOf(values ...string) map[string]bool {
	return sliceSet(values)
}
