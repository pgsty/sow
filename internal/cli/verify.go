package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

func runVerify(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	addCommonFlags(fs, &values)
	var layerFlags, viewFlags, snapshotFlags, targetFlags csvFlag
	fs.Var(&layerFlags, "layer", "verification layer L1, L2, L3, L4, or all (repeatable)")
	fs.Var(&viewFlags, "view", "view to verify (repeatable; defaults to latest)")
	fs.Var(&snapshotFlags, "snapshot", "one immutable <suite>-YYYYMMDD snapshot to verify (conflicts with --view)")
	fs.Var(&targetFlags, "target", "remote target for L2/L3/L4 (cf or cos; repeatable)")
	publicKeyFile := fs.String("gpg-public-key-file", "", "OpenPGP public key used to verify APT/YUM metadata")
	proTokenFile := fs.String("pro-token-file", "", "runtime Pro token file for stable L3/L4 probes (never persisted or logged)")
	jsonOutput := fs.Bool("json", false, "emit the deterministic structured report as JSON")
	maxFindings := fs.Int("max-findings", 1000, "maximum finding details retained; summary counts remain exact")
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow verify [--layer L1[,L2...]] [--view latest | --snapshot <suite>-YYYYMMDD] [--target cf|cos] [--repo NAME] [--os OS] [--arch ARCH] [--pro-token-file FILE] [--json]")
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 || *maxFindings < 1 {
		return withExitCode(ExitUsage, "verify accepts no positional arguments and --max-findings must be positive")
	}
	if len(viewFlags.values()) != 0 && len(snapshotFlags.values()) != 0 {
		return withExitCode(ExitUsage, "verify --view and --snapshot are mutually exclusive")
	}
	if len(snapshotFlags.values()) > 1 {
		return withExitCode(ExitUsage, "verify accepts exactly one --snapshot value")
	}
	layers, err := parseVerifyLayers(layerFlags.values())
	if err != nil {
		return withExitCode(ExitUsage, "%v", err)
	}
	var snapshotID string
	if len(snapshotFlags.values()) == 1 {
		snapshotID = snapshotFlags.values()[0]
		if err := views.ValidateSnapshotID(snapshotID); err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
	}
	var viewsToCheck []string
	if snapshotID == "" {
		viewsToCheck, err = parseVerifyViews(viewFlags.values())
		if err != nil {
			return withExitCode(ExitUsage, "%v", err)
		}
	}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		return err
	}
	if err := validateVerifyTargets(cfg, targetFlags.values()); err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	// An explicit repository/target or target/view mismatch is a pure scope
	// error. Reject it before opening the Pro token, acquiring the state lock, or
	// resolving any provider credential so a typo cannot produce secret or remote
	// side effects. L1 is deliberately local and ignores remote selectors.
	explicitTargets := uniqueSorted(targetFlags.values())
	remoteSelected := verifyLayerSelected(layers, verify.LayerL2) || verifyLayerSelected(layers, verify.LayerL3) || verifyLayerSelected(layers, verify.LayerL4)
	if remoteSelected && len(explicitTargets) != 0 {
		targets := explicitTargets
		if err := validatePublishTargetAffinitySelection(repos, targets, len(values.repos.values()) != 0); err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
		if snapshotID == "" {
			if err := validatePublishTargetViewAffinitySelection(cfg, repos, targets, viewsToCheck); err != nil {
				return withExitCode(ExitConfig, "%v", err)
			}
		}
	}
	var proToken []byte
	if verifyLayerSelected(layers, verify.LayerL3) || verifyLayerSelected(layers, verify.LayerL4) {
		proToken, err = loadProVerificationTokenForIntent(*proTokenFile, viewsToCheck, snapshotID)
		if err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
	}
	defer clearSecret(proToken)
	lock, err := state.AcquireLock(cfg.StatePath(), "verify", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	projectionAudit := inspectProjectionIntentsForAudit(cfg.StatePath())
	if verifyLayerSelected(layers, verify.LayerL1) && projectionAudit.pending() {
		report := verify.Run(ctx, verify.Request{
			Layers: []verify.Layer{verify.LayerL1}, Checks: []verify.Check{projectionAudit.verifyCheck()},
			Workers: values.workers, MaxFindings: *maxFindings,
		})
		return emitVerifyReport(stdout, *jsonOutput, report, false)
	}
	if values.recover {
		if err := requireNoMaterializationIntentBeforeCanonicalMutation(cfg); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
	}
	canonical := state.New(cfg.StatePath())
	if err := prepareCanonicalState(ctx, canonical, values.recover, stdout); err != nil {
		return err
	}
	if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while verify was waiting for the state lock: %v", err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "verify-")
	if err != nil {
		return withExitCode(ExitInternal, "create verify transaction: %v", err)
	}
	defer os.RemoveAll(txDir)
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return withExitCode(ExitConflict, "open CAS: %v", err)
	}

	selected := make(map[verify.Layer]bool, len(layers))
	for _, layer := range layers {
		selected[layer] = true
	}
	var checks []verify.Check
	var remoteNetworkFailure atomic.Bool
	if selected[verify.LayerL1] {
		checks = append(checks, verify.CheckFunc{
			CheckID: "state/materialization-selection", CheckLayer: verify.LayerL1,
			Run: func(_ context.Context, recorder *verify.Recorder) error {
				for _, finding := range inspectProjectionIntentsForAudit(cfg.StatePath()).findings {
					recorder.Add(finding)
				}
				journal, active, err := readMaterializationSelectionJournal(cfg.StatePath())
				if err != nil {
					recorder.Add(verify.Finding{Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryOperational,
						Code: "MATERIALIZATION_JOURNAL_INVALID", Subject: "state/materialization-selection", Message: "materialization recovery journal is unreadable or unsafe"})
					return nil
				}
				if active {
					recorder.Add(verify.Finding{Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryOperational,
						Code: "MATERIALIZATION_RECOVERY_REQUIRED", Subject: "state/materialization-selection", Message: "a directly-hostable selected set is incomplete and must be recovered before release",
						Fields: []verify.Field{{Key: "operation", Value: journal.Operation}, {Key: "phase", Value: string(journal.Phase)}, {Key: "completed_units", Value: fmt.Sprint(len(journal.CompletedUnits))}, {Key: "units", Value: fmt.Sprint(len(journal.Units))}}})
				}
				return nil
			},
		})
		var l1 []verify.Check
		if snapshotID != "" {
			l1, err = buildSnapshotL1Checks(ctx, cfg, canonical, pool, repos, snapshotID, values, *publicKeyFile, txDir)
		} else {
			l1, err = buildL1Checks(ctx, cfg, canonical, pool, repos, viewsToCheck, values, *publicKeyFile, txDir)
		}
		if err != nil {
			return withExitCode(ExitVerification, "prepare L1 checks: %v", err)
		}
		checks = append(checks, l1...)
	}
	if selected[verify.LayerL2] {
		var l2 []verify.Check
		if snapshotID != "" {
			l2, err = buildSnapshotL2Checks(cfg, canonical, repos, snapshotID, values, targetFlags.values(), &remoteNetworkFailure)
		} else {
			l2, err = buildL2Checks(cfg, canonical, repos, viewsToCheck, values, targetFlags.values(), &remoteNetworkFailure)
		}
		if err != nil {
			return withExitCode(ExitConfig, "prepare L2 checks: %v", err)
		}
		checks = append(checks, l2...)
	}
	if selected[verify.LayerL3] {
		var l3 []verify.Check
		if snapshotID != "" {
			l3, err = buildSnapshotL3Checks(cfg, canonical, repos, snapshotID, values, targetFlags.values(), proToken, &remoteNetworkFailure)
		} else {
			l3, err = buildL3Checks(cfg, canonical, repos, viewsToCheck, values, targetFlags.values(), proToken, &remoteNetworkFailure)
		}
		if err != nil {
			return withExitCode(ExitConfig, "prepare L3 checks: %v", err)
		}
		checks = append(checks, l3...)
	}
	if selected[verify.LayerL4] {
		var l4 []verify.Check
		if snapshotID != "" {
			l4, err = buildSnapshotL4Checks(cfg, canonical, repos, snapshotID, values, targetFlags.values(), *publicKeyFile, proToken, txDir, &remoteNetworkFailure)
		} else {
			l4, err = buildL4Checks(cfg, canonical, repos, viewsToCheck, values, targetFlags.values(), *publicKeyFile, proToken, txDir, &remoteNetworkFailure)
		}
		if err != nil {
			return withExitCode(ExitConfig, "prepare L4 checks: %v", err)
		}
		checks = append(checks, l4...)
	}
	report := verify.Run(ctx, verify.Request{Layers: layers, Checks: checks, Workers: values.workers, MaxFindings: *maxFindings})
	return emitVerifyReport(stdout, *jsonOutput, report, remoteNetworkFailure.Load())
}

func verifyLayerSelected(layers []verify.Layer, wanted verify.Layer) bool {
	for _, layer := range layers {
		if layer == wanted {
			return true
		}
	}
	return false
}

func emitVerifyReport(stdout io.Writer, jsonOutput bool, report verify.Report, remoteNetworkFailure bool) error {
	if jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(report); err != nil {
			return withExitCode(ExitInternal, "encode verification report: %v", err)
		}
	} else {
		writeVerifyReport(stdout, report)
	}
	switch report.Exit {
	case verify.ExitSuccess:
		return nil
	case verify.ExitVerification:
		return withExitCode(ExitVerification, "verification outcome=%s", report.Outcome)
	default:
		if remoteNetworkFailure {
			return withExitCode(ExitNetworkAuth, "remote verification incomplete")
		}
		return withExitCode(ExitInternal, "verification incomplete")
	}
}

func parseVerifyLayers(values []string) ([]verify.Layer, error) {
	if len(values) == 0 {
		return []verify.Layer{verify.LayerL1}, nil
	}
	set := make(map[verify.Layer]struct{})
	for _, value := range values {
		if strings.EqualFold(value, "all") {
			return []verify.Layer{verify.LayerL1, verify.LayerL2, verify.LayerL3, verify.LayerL4}, nil
		}
		layer := verify.Layer(strings.ToUpper(value))
		switch layer {
		case verify.LayerL1, verify.LayerL2, verify.LayerL3, verify.LayerL4:
			set[layer] = struct{}{}
		default:
			return nil, fmt.Errorf("unknown verification layer %q", value)
		}
	}
	order := []verify.Layer{verify.LayerL1, verify.LayerL2, verify.LayerL3, verify.LayerL4}
	result := make([]verify.Layer, 0, len(set))
	for _, layer := range order {
		if _, exists := set[layer]; exists {
			result = append(result, layer)
		}
	}
	return result, nil
}

func parseVerifyViews(values []string) ([]string, error) {
	if len(values) == 0 {
		return []string{"latest"}, nil
	}
	result := uniqueSorted(values)
	for _, value := range result {
		if value != "beta" && value != "latest" && value != "stable" {
			return nil, fmt.Errorf("verify currently requires beta, latest, or stable; got %q", value)
		}
	}
	return result, nil
}

func validateVerifyTargets(cfg *config.Config, selected []string) error {
	for _, target := range selected {
		if target != "cf" && target != "cos" {
			return fmt.Errorf("unknown target %q", target)
		}
		if _, exists := cfg.Targets[target]; !exists {
			return fmt.Errorf("target %s is not configured", target)
		}
	}
	return nil
}

func buildL1Checks(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repos []config.Repo, viewNames []string, values commonFlags, publicKeyFile, txDir string) ([]verify.Check, error) {
	needsKey := false
	for _, repo := range repos {
		needsKey = needsKey || repo.Type == "apt" || repo.Type == "yum"
	}
	var aptVerifier *verify.APTVerifier
	var yumVerifier yumrepo.DetachedVerifier
	if needsKey {
		key, err := loadRepositoryPublicKey(cfg, publicKeyFile)
		if err != nil {
			return nil, err
		}
		aptVerifier, err = verify.NewAPTVerifier(bytes.NewReader(key))
		if err != nil {
			return nil, errors.New("invalid repository OpenPGP public key")
		}
		yumVerifier, err = yumrepo.NewOpenPGPVerifier(bytes.NewReader(key), time.Now().UTC())
		if err != nil {
			return nil, errors.New("invalid repository OpenPGP public key")
		}
	}
	var checks []verify.Check
	rpmPackageKeyrings := make(map[string]openpgp.KeyRing)
	cacheVersion, _ := catalog.Version(ctx, cfg.StatePath())
	canonicalHead, headErr := canonical.HeadHash()
	if headErr != nil {
		return nil, headErr
	}
	cacheHead, _ := catalog.CanonicalHead(ctx, cfg.StatePath())
	for _, repo := range repos {
		ref, err := state.RepoRef(repo.ID)
		if err != nil {
			return nil, err
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil {
			return nil, err
		}
		if !exists {
			checks = append(checks, missingCheck("repo/"+repo.ID+"/baseline", verify.LayerL1, "REPO_REF_MISSING", ref.String(), "canonical repository baseline ref is missing (run sow init)"))
			continue
		}
		commitCopy, repoCopy := commit, repo.ID
		checks = append(checks, verify.CacheCheck{
			CheckID: "cache/" + repoCopy,
			Canonical: func() (io.ReadCloser, error) {
				return canonical.OpenPathAt(commitCopy, filepath.ToSlash(filepath.Join("manifests", repoCopy+".tsv")))
			},
			Projection: func() (io.ReadCloser, error) {
				return catalog.OpenManifestProjection(ctx, cfg.StatePath(), repoCopy)
			},
			ExpectedSchema:        catalog.SchemaVersion,
			ActualSchema:          cacheVersion,
			ExpectedCanonicalHead: canonicalHead.String(),
			ActualCanonicalHead:   cacheHead.String(),
		})
	}
	for _, viewName := range viewNames {
		viewConfig := cfg.Views[viewName]
		for _, leaf := range suiteClosedSelectedLeaves(cfg, repos, values) {
			if !viewIncludesRepo(viewConfig, leaf.repo.ID) {
				continue
			}
			ref, _ := state.ViewRef(viewName, leaf.repo.ID, leaf.os, leaf.arch)
			commit, exists, err := canonical.Ref(ref)
			if err != nil {
				return nil, err
			}
			id := "view/" + viewName + "/" + leaf.repo.ID + "/" + leaf.os + "/" + leaf.arch
			if !exists {
				checks = append(checks, missingCheck(id, verify.LayerL1, "VIEW_REF_MISSING", ref.String(), "configured view ref is missing"))
				continue
			}
			viewPath, _ := state.ViewPath(viewName, leaf.repo.ID, leaf.os, leaf.arch)
			commitCopy, pathCopy, repoCopy := commit, viewPath, leaf.repo
			publicView := viewConfig.Access == "public"
			var validateEntry func(views.Entry) error
			if repoCopy.Type == "asset" {
				validateEntry = func(entry views.Entry) error {
					if err := validateAssetProjectionPath(repoCopy, entry.Path); err != nil {
						return err
					}
					if publicView {
						destination := repoCopy
						destination.DefaultPool = "public"
						if _, err := requireOfflineArchiveTaintAdmission(canonical, destination, entry.SHA256, entry.Size); err != nil {
							return fmt.Errorf("public asset %s violates canonical archive taint: %w", entry.Path, err)
						}
					}
					return nil
				}
			}
			checks = append(checks, verify.ViewCheck{
				CheckID: id, Open: func() (io.ReadCloser, error) { return canonical.OpenPathAt(commitCopy, pathCopy) },
				Repo: leaf.repo.ID, OS: leaf.os, Arch: leaf.arch, Public: publicView, ValidateEntry: validateEntry,
			})
		}
		for _, repo := range repos {
			if !viewIncludesRepo(viewConfig, repo.ID) {
				continue
			}
			switch repo.Type {
			case "asset":
				expected, err := stageAssetVerificationManifest(canonical, repo, viewName, txDir)
				if err != nil {
					if errors.Is(err, os.ErrNotExist) {
						continue
					}
					return nil, err
				}
				root := filepath.Join(cfg.Root, filepath.FromSlash(repositoryViewTarget(repo.Path, viewName)))
				checks = append(checks, verify.FilesystemCheck{CheckID: "asset/" + viewName + "/" + repo.ID, Root: root, Scope: manifest.Scope{Path: "."}, Expected: verify.FileStream(expected), Workers: values.workers, ChunkEntries: values.chunk, TempDir: txDir})
			case "apt":
				root := filepath.Join(cfg.Root, filepath.FromSlash(repositoryViewTarget(repo.Path, viewName)))
				original, exists := cfg.RepoByName(repo.ID)
				if !exists || original.Type != "apt" || original.APT == nil {
					return nil, fmt.Errorf("APT repository %s is absent from canonical configuration", repo.ID)
				}
				selectedSuites := []string(nil)
				if !sameStringSet(original.APT.Suites, repo.APT.Suites) {
					selectedSuites = append([]string(nil), repo.APT.Suites...)
				}
				checks = append(checks, verify.APTCheck{
					CheckID: "apt/" + viewName + "/" + repo.ID, Root: root,
					ExpectedSuites: original.APT.Suites, SelectedSuites: selectedSuites,
					ExpectedSuiteComponents: aptSuiteComponentContract(original.APT),
					Verifier:                aptVerifier, VerifyAt: time.Now().UTC(), Workers: values.workers, ChunkEntries: values.chunk, TempDir: txDir,
				})
			case "yum":
				packageKeyring := rpmPackageKeyrings[repo.ID]
				if packageKeyring == nil {
					loaded, _, loadErr := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
					if loadErr != nil || loaded == nil {
						return nil, errors.Join(loadErr, fmt.Errorf("repo %s has no usable RPM package keyring", repo.ID))
					}
					packageKeyring = loaded
					rpmPackageKeyrings[repo.ID] = packageKeyring
				}
				for _, arch := range repo.Arches {
					if !matchesValue(arch, values.arches.values()) {
						continue
					}
					effective, err := repo.PathForArch(arch)
					if err != nil {
						return nil, err
					}
					compression := yumrepo.CompressionZstd
					if repo.YUM.Compression == "gzip" {
						compression = yumrepo.CompressionGzip
					}
					root := filepath.Join(cfg.Root, filepath.FromSlash(repositoryViewTarget(effective, viewName)))
					checks = append(checks, verify.YUMCheck{CheckID: "yum/" + viewName + "/" + repo.ID + "/" + arch, Root: root, Compression: compression, Verifier: yumVerifier, PackageKeyring: packageKeyring, VerifyAt: time.Now().UTC(), Workers: values.workers, ChunkEntries: values.chunk, TempDir: txDir})
				}
			}
		}
	}
	compatibility, err := selectedLatestYUMCompatibilityForViews(cfg, repos, viewNames, values)
	if err != nil {
		return nil, err
	}
	for _, projection := range compatibility {
		projectionCopy := projection
		checks = append(checks, verify.CheckFunc{
			CheckID: "yum-compat/latest/" + projection.ID, CheckLayer: verify.LayerL1,
			Run: func(runCtx context.Context, recorder *verify.Recorder) error {
				stage, err := auditYUMCompatibilityStage(runCtx, cfg, canonical, pool, projectionCopy, txDir, values)
				if err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return err
					}
					recorder.Add(verify.Finding{Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
						Code: "YUM_COMPATIBILITY_STAGE_CLOSURE_INVALID", Subject: projectionCopy.ID,
						Message: "cross-EL compatibility stage, immutable roots, CAS, serving link, or signed metadata closure is invalid",
						Fields:  []verify.Field{{Key: "stage", Value: string(stage)}, {Key: "reason", Value: err.Error()}}})
				}
				return nil
			},
		})
	}
	servingChecks, err := buildLocalServingL1Checks(cfg, canonical, pool, repos, viewNames, values, txDir)
	if err != nil {
		return nil, err
	}
	checks = append(checks, servingChecks...)
	casCheck, err := buildGlobalCASCheck(ctx, cfg, canonical, pool, txDir)
	if err != nil {
		return nil, err
	}
	checks = append(checks, casCheck)
	return checks, nil
}

func selectedLatestYUMCompatibilityForViews(cfg *config.Config, repos []config.Repo, viewNames []string, values commonFlags) ([]config.YUMCompatibilityProjection, error) {
	latest := false
	for _, viewName := range viewNames {
		latest = latest || viewName == "latest"
	}
	if !latest {
		return nil, nil
	}
	leaves := suiteClosedSelectedLeaves(cfg, repos, values)
	return selectedYUMCompatibilityProjections(cfg, materializeCanonicalSource{ID: "latest", Public: true}, leaves, values)
}

// selectedLatestYUMCompatibilityForTarget keeps compatibility projections on
// the same remote as their canonical source owner. The frozen projection has
// its own public root, but it deliberately inherits target affinity rather
// than becoming a globally replicated repository.
func selectedLatestYUMCompatibilityForTarget(cfg *config.Config, repos []config.Repo, target string, viewNames []string, values commonFlags) ([]config.YUMCompatibilityProjection, error) {
	return selectedLatestYUMCompatibilityForViews(cfg, reposPublishingToTarget(repos, target), viewNames, values)
}

func aptSuiteComponentContract(apt *config.APTConfig) map[string][]string {
	if apt == nil {
		return nil
	}
	result := make(map[string][]string, len(apt.Suites))
	for _, suite := range apt.Suites {
		result[suite] = apt.ComponentsForSuite(suite)
	}
	return result
}

// buildSnapshotL1Checks verifies the immutable canonical leaf set and the
// default hostable materialization derived from those exact commits. Snapshot
// verification never falls back to stable/latest refs: a missing leaf or
// materialization is explicit coverage failure evidence.
func buildSnapshotL1Checks(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repos []config.Repo, snapshotID string, values commonFlags, publicKeyFile, txDir string) ([]verify.Check, error) {
	leaves, err := selectedSnapshotLeaves(cfg, repos, values, snapshotID)
	if err != nil {
		return nil, err
	}
	if len(leaves) == 0 {
		return []verify.Check{missingCheck("snapshot/"+snapshotID+"/coverage", verify.LayerL1, "SNAPSHOT_REF_COVERAGE_MISSING", snapshotID, "selectors matched no repository leaves for this snapshot suite")}, nil
	}
	needsKey := false
	for _, leaf := range leaves {
		needsKey = needsKey || leaf.repo.Type == "apt" || leaf.repo.Type == "yum"
	}
	var aptVerifier *verify.APTVerifier
	var yumVerifier yumrepo.DetachedVerifier
	if needsKey {
		key, err := loadRepositoryPublicKey(cfg, publicKeyFile)
		if err != nil {
			return nil, err
		}
		aptVerifier, err = verify.NewAPTVerifier(bytes.NewReader(key))
		if err != nil {
			return nil, errors.New("invalid repository OpenPGP public key")
		}
		yumVerifier, err = yumrepo.NewOpenPGPVerifier(bytes.NewReader(key), time.Now().UTC())
		if err != nil {
			return nil, errors.New("invalid repository OpenPGP public key")
		}
	}

	checks := make([]verify.Check, 0, len(leaves)*2+1)
	rpmPackageKeyrings := make(map[string]openpgp.KeyRing)
	materializedRoot := filepath.Join(cfg.Root, filepath.FromSlash(defaultMaterializationTarget(snapshotID, true)))
	presentByRepo := make(map[string][]viewLeaf)
	for _, leaf := range leaves {
		ref, err := state.SnapshotRef(snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return nil, err
		}
		canonicalPath, err := state.SnapshotPath(snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return nil, err
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil {
			return nil, err
		}
		id := "snapshot/" + snapshotID + "/" + leaf.repo.ID + "/" + leaf.os + "/" + leaf.arch
		if !exists {
			checks = append(checks, missingCheck(id, verify.LayerL1, "SNAPSHOT_REF_MISSING", ref.String(), "immutable snapshot ref is missing"))
			continue
		}
		commitCopy, pathCopy, leafCopy := commit, canonicalPath, leaf
		var validateEntry func(views.Entry) error
		if leafCopy.repo.Type == "asset" {
			validateEntry = func(entry views.Entry) error { return validateAssetProjectionPath(leafCopy.repo, entry.Path) }
		}
		checks = append(checks, verify.ViewCheck{
			CheckID: id,
			Open: func() (io.ReadCloser, error) {
				return canonical.OpenPathAt(commitCopy, pathCopy)
			},
			Repo: leafCopy.repo.ID, OS: leafCopy.os, Arch: leafCopy.arch, Public: false, ValidateEntry: validateEntry,
		})
		presentByRepo[leaf.repo.ID] = append(presentByRepo[leaf.repo.ID], leaf)
	}
	for _, repo := range repos {
		repoLeaves := presentByRepo[repo.ID]
		if len(repoLeaves) == 0 {
			continue
		}
		switch repo.Type {
		case "asset":
			expected, err := stageSnapshotAssetVerificationManifest(canonical, repo, snapshotID, txDir)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					checks = append(checks, missingCheck("asset/snapshot/"+snapshotID+"/"+repo.ID, verify.LayerL1, "SNAPSHOT_ASSET_REF_MISSING", repo.ID, "snapshot asset manifest is missing"))
					continue
				}
				return nil, err
			}
			root := filepath.Join(materializedRoot, filepath.FromSlash(repo.Path))
			checks = append(checks, verify.FilesystemCheck{CheckID: "asset/snapshot/" + snapshotID + "/" + repo.ID, Root: root, Scope: manifest.Scope{Path: "."}, Expected: verify.FileStream(expected), Workers: values.workers, ChunkEntries: values.chunk, TempDir: txDir})
		case "apt":
			root := filepath.Join(materializedRoot, filepath.FromSlash(repo.Path))
			expected, err := stageSnapshotPayloadVerificationManifest(canonical, repo, snapshotID, repoLeaves, repo.Path, txDir)
			if err != nil {
				return nil, err
			}
			sourceSuite, err := views.SnapshotSuite(snapshotID)
			if err != nil {
				return nil, err
			}
			checks = append(checks, verify.FilesystemCheck{CheckID: "apt/snapshot/" + snapshotID + "/" + repo.ID + "/payload", Root: root, Scope: manifest.Scope{Path: "pool"}, Expected: verify.FileStream(expected), Workers: values.workers, ChunkEntries: values.chunk, TempDir: txDir})
			checks = append(checks, verify.APTCheck{
				CheckID: "apt/snapshot/" + snapshotID + "/" + repo.ID, Root: root,
				ExpectedSuites: []string{snapshotID}, ExpectedSuiteComponents: map[string][]string{snapshotID: repo.APT.ComponentsForSuite(sourceSuite)},
				Verifier: aptVerifier, VerifyAt: time.Now().UTC(), Workers: values.workers, ChunkEntries: values.chunk, TempDir: txDir,
			})
		case "yum":
			packageKeyring := rpmPackageKeyrings[repo.ID]
			if packageKeyring == nil {
				loaded, _, loadErr := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
				if loadErr != nil || loaded == nil {
					return nil, errors.Join(loadErr, fmt.Errorf("repo %s has no usable RPM package keyring", repo.ID))
				}
				packageKeyring = loaded
				rpmPackageKeyrings[repo.ID] = packageKeyring
			}
			for _, leaf := range repoLeaves {
				effective, err := repo.PathForArch(leaf.arch)
				if err != nil {
					return nil, err
				}
				compression := yumrepo.CompressionZstd
				if repo.YUM.Compression == "gzip" {
					compression = yumrepo.CompressionGzip
				}
				root := filepath.Join(materializedRoot, filepath.FromSlash(effective))
				expected, err := stageSnapshotPayloadVerificationManifest(canonical, repo, snapshotID, []viewLeaf{leaf}, effective, txDir)
				if err != nil {
					return nil, err
				}
				checks = append(checks, verify.FilesystemCheck{CheckID: "yum/snapshot/" + snapshotID + "/" + repo.ID + "/" + leaf.arch + "/payload", Root: root, Scope: manifest.Scope{Path: "Packages"}, Expected: verify.FileStream(expected), Workers: values.workers, ChunkEntries: values.chunk, TempDir: txDir})
				checks = append(checks, verify.YUMCheck{CheckID: "yum/snapshot/" + snapshotID + "/" + repo.ID + "/" + leaf.arch, Root: root, Compression: compression, Verifier: yumVerifier, PackageKeyring: packageKeyring, VerifyAt: time.Now().UTC(), Workers: values.workers, ChunkEntries: values.chunk, TempDir: txDir})
			}
		}
	}
	casCheck, err := buildGlobalCASCheck(ctx, cfg, canonical, pool, txDir)
	if err != nil {
		return nil, err
	}
	checks = append(checks, casCheck)
	return checks, nil
}

func selectedSnapshotLeaves(cfg *config.Config, repos []config.Repo, values commonFlags, snapshotID string) ([]viewLeaf, error) {
	suite, err := views.SnapshotSuite(snapshotID)
	if err != nil {
		return nil, err
	}
	var result []viewLeaf
	for _, leaf := range suiteClosedSelectedLeaves(cfg, repos, values) {
		if leaf.repo.Type == "asset" || leaf.os == suite {
			result = append(result, leaf)
		}
	}
	return result, nil
}

func buildGlobalCASCheck(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, txDir string) (verify.Check, error) {
	roots, _, err := collectCanonicalRoots(ctx, canonical, pool, cfg.State.CASHistoryCommits)
	if err != nil {
		return nil, err
	}
	rootManifest := filepath.Join(txDir, "cas-roots.tsv")
	file, err := os.OpenFile(rootManifest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	writeErr := roots.WriteManifest(file)
	closeErr := errors.Join(file.Sync(), file.Close())
	if writeErr != nil || closeErr != nil {
		return nil, errors.Join(writeErr, closeErr)
	}
	return verify.CASCheck{CheckID: "cas/all-history", Store: pool, Roots: []verify.NamedManifest{{Name: "canonical-history", Open: verify.FileStream(rootManifest)}}}, nil
}

func stageAssetVerificationManifest(canonical *state.Store, repo config.Repo, viewName, txDir string) (string, error) {
	ref, err := state.ViewRef(viewName, repo.ID, "all", "all")
	if err != nil {
		return "", err
	}
	commit, exists, err := canonical.Ref(ref)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", os.ErrNotExist
	}
	viewPath, _ := state.ViewPath(viewName, repo.ID, "all", "all")
	reader, err := canonical.OpenPathAt(commit, viewPath)
	if err != nil {
		return "", err
	}
	fullPath := filepath.Join(txDir, "asset-"+viewName+"-"+repo.ID+"-full.tsv")
	full, err := os.OpenFile(fullPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		reader.Close()
		return "", err
	}
	_, _, projectErr := views.ProjectManifest([]views.ProjectionInput{{Label: ref.String(), Reader: reader}}, full)
	closeErr := errors.Join(reader.Close(), full.Sync(), full.Close())
	if projectErr != nil || closeErr != nil {
		return "", errors.Join(projectErr, closeErr)
	}
	relativePath := filepath.Join(txDir, "asset-"+viewName+"-"+repo.ID+"-relative.tsv")
	if err := stripManifestPrefix(fullPath, relativePath, repo.Path); err != nil {
		return "", err
	}
	return relativePath, nil
}

func stageSnapshotAssetVerificationManifest(canonical *state.Store, repo config.Repo, snapshotID, txDir string) (string, error) {
	ref, err := state.SnapshotRef(snapshotID, repo.ID, "all", "all")
	if err != nil {
		return "", err
	}
	commit, exists, err := canonical.Ref(ref)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", os.ErrNotExist
	}
	canonicalPath, err := state.SnapshotPath(snapshotID, repo.ID, "all", "all")
	if err != nil {
		return "", err
	}
	reader, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return "", err
	}
	fullPath := filepath.Join(txDir, "asset-snapshot-"+snapshotID+"-"+repo.ID+"-full.tsv")
	full, err := os.OpenFile(fullPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		reader.Close()
		return "", err
	}
	_, _, projectErr := views.ProjectManifest([]views.ProjectionInput{{Label: ref.String(), Reader: reader}}, full)
	closeErr := errors.Join(reader.Close(), full.Sync(), full.Close())
	if projectErr != nil || closeErr != nil {
		return "", errors.Join(projectErr, closeErr)
	}
	relativePath := filepath.Join(txDir, "asset-snapshot-"+snapshotID+"-"+repo.ID+"-relative.tsv")
	if err := stripManifestPrefix(fullPath, relativePath, repo.Path); err != nil {
		return "", err
	}
	return relativePath, nil
}

func stageSnapshotPayloadVerificationManifest(canonical *state.Store, repo config.Repo, snapshotID string, leaves []viewLeaf, repositoryPrefix, txDir string) (string, error) {
	var inputs []views.ProjectionInput
	var readers []io.ReadCloser
	closeReaders := func() error {
		var closeErr error
		for _, reader := range readers {
			closeErr = errors.Join(closeErr, reader.Close())
		}
		readers = nil
		return closeErr
	}
	defer closeReaders()
	for _, leaf := range leaves {
		ref, err := state.SnapshotRef(snapshotID, repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return "", err
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil {
			return "", err
		}
		if !exists {
			return "", os.ErrNotExist
		}
		canonicalPath, err := state.SnapshotPath(snapshotID, repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return "", err
		}
		reader, err := canonical.OpenPathAt(commit, canonicalPath)
		if err != nil {
			return "", err
		}
		readers = append(readers, reader)
		inputs = append(inputs, views.ProjectionInput{Label: ref.String(), Reader: reader})
	}
	identity := fmt.Sprintf("%06d", len(leaves))
	if len(leaves) != 0 {
		identity = leaves[0].os + "-" + leaves[0].arch + "-" + identity
	}
	fullPath := filepath.Join(txDir, "payload-snapshot-"+snapshotID+"-"+repo.ID+"-"+identity+"-full.tsv")
	full, err := os.OpenFile(fullPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	_, _, projectErr := views.ProjectManifest(inputs, full)
	closeErr := errors.Join(full.Sync(), full.Close(), closeReaders())
	if projectErr != nil || closeErr != nil {
		return "", errors.Join(projectErr, closeErr)
	}
	relativePath := strings.TrimSuffix(fullPath, "-full.tsv") + "-relative.tsv"
	if err := stripManifestPrefix(fullPath, relativePath, repositoryPrefix); err != nil {
		return "", err
	}
	return relativePath, nil
}

func buildL2Checks(cfg *config.Config, canonical *state.Store, repos []config.Repo, viewNames []string, values commonFlags, selectedTargets []string, networkFailure *atomic.Bool) ([]verify.Check, error) {
	var checks []verify.Check
	for _, target := range verifyTargetNames(cfg, selectedTargets) {
		targetRepos := reposPublishingToTarget(repos, target)
		if len(targetRepos) == 0 {
			continue
		}
		viewLeaves := make(map[string][]viewLeaf, len(viewNames))
		selectedLeafCount := 0
		for _, viewName := range viewNames {
			viewLeaves[viewName] = selectedVerificationViewLeaves(cfg, targetRepos, target, viewName, values)
			selectedLeafCount += len(viewLeaves[viewName])
		}
		if selectedLeafCount == 0 {
			continue
		}
		client, err := newPublishTargetClient(cfg, target, "latest", false)
		if err != nil {
			return nil, fmt.Errorf("target %s: %w", target, err)
		}
		checks = append(checks, buildRemoteL2Check(canonical, cfg, target, client, networkFailure))
		for _, viewName := range viewNames {
			leaves := viewLeaves[viewName]
			if len(leaves) == 0 {
				continue
			}
			identityID := "remote/" + target + "/" + viewName + "/identity"
			publication, stateErr := loadCommittedVerificationStateForConfig(cfg, canonical, target, viewName, "")
			if stateErr != nil {
				checks = append(checks, verificationStateCheck(identityID, verify.LayerL2, target, stateErr))
			} else {
				configSHA, err := publicationConfigSHA256ForGeneration(cfg, publication.generation)
				if err != nil {
					return nil, err
				}
				if publication.generation.ConfigSHA256 != configSHA {
					checks = append(checks, verificationStateCheck(identityID, verify.LayerL2, target, &verificationStateError{code: "REMOTE_CONFIG_DRIFT", category: verify.CategoryDrift, message: "current configuration differs from the committed publication generation"}))
				} else {
					keyMatches, err := generationRepositoryTrustMatches(cfg, publication.generation)
					if err != nil {
						return nil, err
					}
					if !keyMatches {
						checks = append(checks, verificationStateCheck(identityID, verify.LayerL2, target, &verificationStateError{code: "REMOTE_REPOSITORY_KEY_DRIFT", category: verify.CategoryDrift, message: "current repository public key differs from the committed generation"}))
					}
				}
			}
			for _, leaf := range leaves {
				desiredRef, _ := state.ViewRef(viewName, leaf.repo.ID, leaf.os, leaf.arch)
				desired, desiredExists, _ := canonical.Ref(desiredRef)
				remoteRef, _ := state.RemoteRef(target, viewName, leaf.repo.ID, leaf.os, leaf.arch)
				remote, remoteExists, _ := canonical.Ref(remoteRef)
				id := "remote/" + target + "/" + viewName + "/" + leaf.repo.ID + "/" + leaf.os + "/" + leaf.arch
				switch {
				case !desiredExists:
					checks = append(checks, missingCheck(id, verify.LayerL2, "LOCAL_REF_MISSING", desiredRef.String(), "local desired ref is missing"))
				case !remoteExists:
					checks = append(checks, missingCheck(id, verify.LayerL2, "REMOTE_REF_MISSING", remoteRef.String(), "published target ref is missing"))
				default:
					checks = append(checks, verify.RefPointerCheck{CheckID: id, AtLayer: verify.LayerL2, RefName: remoteRef.String(), ExpectedCommit: desired.String(), ActualCommit: remote.String()})
				}
			}
		}
	}
	if len(checks) == 0 {
		checks = append(checks, missingCheck("remote/coverage", verify.LayerL2, "REMOTE_TARGET_COVERAGE_MISSING", "L2", "selected repositories and views match no configured publication target"))
	}
	return checks, nil
}

// selectedVerificationViewLeaves applies both independent publication target
// affinity and the configured view repository scope before a verifier derives
// ref or client expectations. Callers may pass an already target-narrowed repo
// slice; the repeated affinity check is deliberate and keeps this helper safe
// for direct use by every L2/L4 builder.
func selectedVerificationViewLeaves(cfg *config.Config, repos []config.Repo, target, viewName string, values commonFlags) []viewLeaf {
	if cfg == nil {
		return nil
	}
	view, exists := cfg.Views[viewName]
	if !exists {
		return nil
	}
	targetRepos := reposPublishingToTarget(repos, target)
	var result []viewLeaf
	for _, leaf := range selectedLeaves(targetRepos, values) {
		if viewIncludesRepo(view, leaf.repo.ID) {
			result = append(result, leaf)
		}
	}
	return result
}

func selectedVerificationSnapshotLeaves(cfg *config.Config, repos []config.Repo, target, snapshotID string, values commonFlags) ([]viewLeaf, error) {
	return selectedSnapshotLeaves(cfg, reposPublishingToTarget(repos, target), values, snapshotID)
}

func missingCheck(id string, layer verify.Layer, code, subject, message string) verify.Check {
	return verify.CheckFunc{CheckID: id, CheckLayer: layer, Run: func(_ context.Context, recorder *verify.Recorder) error {
		recorder.Add(verify.Finding{Layer: layer, Severity: verify.SeverityCritical, Category: verify.CategoryCoverage, Code: code, Subject: subject, Message: message})
		return nil
	}}
}

func repositoryViewTarget(repoPath, viewName string) string {
	switch viewName {
	case "beta":
		return filepath.ToSlash(filepath.Join(config.StateDirectory, "materialized", "beta", repoPath))
	case "stable":
		return filepath.ToSlash(filepath.Join(config.StateDirectory, "origin", "gated", repoPath))
	default:
		return repoPath
	}
}

func loadRepositoryPublicKey(cfg *config.Config, override string) ([]byte, error) {
	keyPath := override
	if keyPath == "" {
		keyPath = cfg.GPG.PublicKey
	}
	if keyPath == "" {
		return nil, errors.New("gpg.public_key or --gpg-public-key-file is required for package repository verification")
	}
	_, packets, err := loadRepositoryPublicTrustAnchor(cfg.Path, keyPath)
	if err != nil {
		return nil, err
	}
	return packets, nil
}

func writeVerifyReport(destination io.Writer, report verify.Report) {
	fmt.Fprintf(destination, "verify outcome=%s exit=%d info=%d warnings=%d errors=%d critical=%d operational=%d suppressed=%d\n",
		report.Outcome, report.Exit, report.Summary.Info, report.Summary.Warnings, report.Summary.Errors,
		report.Summary.Critical, report.Summary.Operational, report.Summary.Suppressed)
	for _, finding := range report.Findings {
		fmt.Fprintf(destination, "finding layer=%s severity=%s category=%s code=%s subject=%q message=%q", finding.Layer, finding.Severity, finding.Category, finding.Code, finding.Subject, finding.Message)
		for _, field := range finding.Fields {
			fmt.Fprintf(destination, " %s=%q", field.Key, field.Value)
		}
		fmt.Fprintln(destination)
	}
}
