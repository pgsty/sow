package cli

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
	"golang.org/x/sys/unix"
)

type nginxCompatibilityAdmissionHookKey struct{}
type nginxCompatibilityAdmissionHook func(phase, projection string) error

// withNginxCompatibilityAdmissionHook is a deterministic test seam for
// repository-coordinate replacement. Production callers never install it.
func withNginxCompatibilityAdmissionHook(ctx context.Context, hook nginxCompatibilityAdmissionHook) context.Context {
	return context.WithValue(ctx, nginxCompatibilityAdmissionHookKey{}, hook)
}

func runNginxCompatibilityAdmissionHook(ctx context.Context, phase, projection string) error {
	if hook, ok := ctx.Value(nginxCompatibilityAdmissionHookKey{}).(nginxCompatibilityAdmissionHook); ok && hook != nil {
		return hook(phase, projection)
	}
	return nil
}

func renderMaterializeNginxInclude(ctx context.Context, cfg *config.Config, repos []config.Repo, view, targetRoot, authUserFile, outputPath string, values commonFlags, stdout io.Writer) (resultErr error) {
	session, err := openLocalReadAdmission(cfg)
	if err != nil {
		return withExitCode(ExitVerification, "Nginx read admission: %v", err)
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close()) }()
	rawCompatibility, activeCompatibility, err := admittedNginxCompatibilityWithSession(ctx, cfg, repos, view, targetRoot, values, session)
	if err != nil {
		return withExitCode(ExitVerification, "Nginx compatibility admission: %v", err)
	}
	if err := runNginxCompatibilityAdmissionHook(ctx, "after-compat-admission", view); err != nil {
		return withExitCode(ExitVerification, "Nginx read admission hook: %v", err)
	}
	if err := validateNginxIncludeTrustWithSession(cfg, repos, view, session); err != nil {
		return withExitCode(ExitConfig, "Nginx include trust projection: %v", err)
	}
	if err := runNginxCompatibilityAdmissionHook(ctx, "after-trust-admission", view); err != nil {
		return withExitCode(ExitVerification, "Nginx trust admission hook: %v", err)
	}
	body, err := serving.RenderNginxInclude(cfg, repos, serving.NginxIncludeOptions{
		View: view, Root: targetRoot, BasicAuthUserFile: authUserFile,
		RawCompatibilityIDs: rawCompatibility, ActiveCompatibilityIDs: activeCompatibility,
	})
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	if err := admitNginxOrdinaryRoutesWithSession(ctx, cfg, repos, view, targetRoot, values, session); err != nil {
		return withExitCode(ExitVerification, "Nginx ordinary route admission: %v", err)
	}
	if err := runNginxCompatibilityAdmissionHook(ctx, "after-ordinary-admission", view); err != nil {
		return withExitCode(ExitVerification, "Nginx read admission hook: %v", err)
	}
	if err := session.Verify(targetRoot); err != nil {
		return withExitCode(ExitVerification, "Nginx final read admission: %v", err)
	}
	if outputPath == "-" {
		if _, err := stdout.Write(body); err != nil {
			return withExitCode(ExitInternal, "write Nginx include to stdout: %v", err)
		}
		return nil
	}
	if err := writeNginxIncludeAtomicallyWithBarrier(cfg, targetRoot, outputPath, body, nil, func() error {
		return session.Verify(targetRoot)
	}); err != nil {
		return withExitCode(ExitConflict, "write Nginx include: %v", err)
	}
	digest := sha256.Sum256(body)
	if _, err := fmt.Fprintf(stdout, "nginx_include view=%s path=%s bytes=%d sha256=%s\n", view, outputPath, len(body), hex.EncodeToString(digest[:])); err != nil {
		return withExitCode(ExitInternal, "write Nginx include receipt: %v", err)
	}
	return nil
}

// admittedNginxCompatibility converts durable compatibility state into the
// two independent serving capabilities understood by the route renderer. S1
// adoption proves the pre-cutover raw bridge. S2 freeze alone never enables a
// generation/pointer/trust route. The append-only cutover/rollback ledger is
// handled as a distinct S3 authority; until that ledger is validated, its mere
// presence fails closed rather than falling back to the S0 validator.
func admittedNginxCompatibility(ctx context.Context, cfg *config.Config, repos []config.Repo, viewName, targetRoot string, values commonFlags) (raw []string, active []string, resultErr error) {
	session, err := openLocalReadAdmission(cfg)
	if err != nil {
		return nil, nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close()) }()
	raw, active, resultErr = admittedNginxCompatibilityWithSession(ctx, cfg, repos, viewName, targetRoot, values, session)
	if resultErr == nil {
		resultErr = session.Verify(targetRoot)
	}
	return raw, active, resultErr
}

func admittedNginxCompatibilityWithSession(ctx context.Context, cfg *config.Config, repos []config.Repo, viewName, targetRoot string, values commonFlags, session *localReadAdmission) (raw []string, active []string, resultErr error) {
	if ctx == nil || cfg == nil {
		return nil, nil, errors.New("Nginx compatibility admission dependencies are unavailable")
	}
	if session == nil || session.root == nil {
		return nil, nil, errors.New("Nginx compatibility read admission is unavailable")
	}
	if viewName != "latest" || len(cfg.CompatibilityProjections) == 0 {
		return nil, nil, nil
	}
	view, exists := cfg.Views[viewName]
	if !exists {
		return nil, nil, fmt.Errorf("view %q is not configured", viewName)
	}
	selectedOwners := make(map[string]struct{})
	for _, repo := range repos {
		if repo.IsActive() && repo.Type == "yum" && viewIncludesRepo(view, repo.ID) {
			selectedOwners[repo.ID] = struct{}{}
		}
	}
	projections := make([]config.YUMCompatibilityProjection, 0, len(cfg.CompatibilityProjections))
	for _, projection := range cfg.CompatibilityProjections {
		if projection.Source.View != viewName {
			continue
		}
		if _, selected := selectedOwners[projection.Source.Repo]; selected {
			projections = append(projections, projection)
		}
	}
	if len(projections) == 0 {
		return nil, nil, nil
	}
	sort.Slice(projections, func(i, j int) bool { return projections[i].ID < projections[j].ID })
	if session.canonical == nil {
		return nil, nil, nil
	}
	configuredRoot, err := resolveNginxPathPrefix(cfg.Root)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve configured compatibility root: %w", err)
	}
	servedRoot, err := resolveNginxPathPrefix(targetRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve served compatibility root: %w", err)
	}
	if configuredRoot != servedRoot {
		return nil, nil, fmt.Errorf("compatibility raw bridge belongs to configured root %s, not explicit target %s", configuredRoot, servedRoot)
	}
	canonical := session.canonical
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return nil, nil, errors.Join(err, errors.New("compatibility canonical HEAD is unavailable"))
	}
	if err := session.requireNoMutationLock(); err != nil {
		return nil, nil, err
	}
	// Render-only admission must not create lock, transaction, CAS, or serving
	// paths below the repository. A system temporary directory holds bounded
	// scan manifests. Git, CAS, canonical state and the served tree are read
	// only through retained capabilities; the final defer proves those public
	// coordinates still name the retained objects.
	txDir, err := os.MkdirTemp("", "sow-nginx-compatibility-admission-")
	if err != nil {
		return nil, nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(txDir)) }()
	pool, err := session.OpenPool()
	if err != nil {
		return nil, nil, fmt.Errorf("open compatibility CAS for route admission: %w", err)
	}
	binding := session.Binding()

	for _, projection := range projections {
		carrier, carrierExists := cfg.RepoByName(projection.Carrier)
		owner, ownerExists := cfg.RepoByName(projection.Source.Repo)
		if !carrierExists || carrier.Type != "yum" || !ownerExists || owner.Type != "yum" || owner.YUM == nil {
			return nil, nil, fmt.Errorf("compatibility projection %s carrier or owner is unavailable", projection.ID)
		}
		ledgerPath, _ := state.YUMCompatibilityCutoverPath(projection.ID)
		_, ledgerExists, err := readCanonicalBytesAt(canonical, head, ledgerPath, maximumYUMCompatibilityLedgerBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect compatibility %s append-only cutover ledger: %w", projection.ID, err)
		}
		if err := runNginxCompatibilityAdmissionHook(ctx, "before-stage-audit", projection.ID); err != nil {
			return nil, nil, fmt.Errorf("compatibility %s admission hook: %w", projection.ID, err)
		}
		stage, stageErr := auditYUMCompatibilityStageWithBinding(ctx, cfg, canonical, pool, projection, txDir, values, binding)
		afterStageErr := runNginxCompatibilityAdmissionHook(ctx, "after-stage-audit", projection.ID)
		if stageErr != nil || afterStageErr != nil {
			return nil, nil, fmt.Errorf("validate compatibility %s route stage: %w", projection.ID, errors.Join(stageErr, afterStageErr))
		}
		if err := admitRawNginxCompatibilityHostability(ctx, cfg, canonical, carrier, projection, txDir, values, session); err != nil {
			return nil, nil, fmt.Errorf("validate compatibility %s raw bridge hostability: %w", projection.ID, err)
		}
		if ledgerExists {
			if stage == yumCompatibilityStageS0 || stage == yumCompatibilityStageS1 {
				return nil, nil, fmt.Errorf("compatibility projection %s has cutover authority before an immutable S2 freeze", projection.ID)
			}
			ledger, err := loadYUMCompatibilityCutoverStateAt(canonical, plumbing.ZeroHash, projection.ID)
			if err != nil {
				return nil, nil, fmt.Errorf("validate compatibility %s append-only cutover ledger: %w", projection.ID, err)
			}
			if len(ledger.Events) == 0 || stage != ledger.Stage {
				return nil, nil, fmt.Errorf("compatibility projection %s has %s cutover authority without matching %s local state", projection.ID, ledger.Stage, stage)
			}
		}
		raw = append(raw, projection.ID)
		switch stage {
		case yumCompatibilityStageS0, yumCompatibilityStageS1, yumCompatibilityStageS2, yumCompatibilityStageRolledBack:
			// Raw compatibility remains available before cutover and after an
			// append-only rollback. S2 alone never admits generation, mirrorlist,
			// or frozen trust URLs.
		case yumCompatibilityStageS3:
			if err := validateActiveNginxCompatibilityClosureWithBinding(ctx, cfg, canonical, pool, projection, targetRoot, txDir, values, binding); err != nil {
				return nil, nil, fmt.Errorf("validate active compatibility %s route closure: %w", projection.ID, err)
			}
			active = append(active, projection.ID)
		default:
			return nil, nil, fmt.Errorf("compatibility projection %s has unsupported stage %s", projection.ID, stage)
		}
	}
	return raw, active, nil
}

// admitRawNginxCompatibilityHostability proves the worker-visible permission
// closure for the exact S0 baseline that the raw prefix route exposes. The
// canonical manifest is streamed; no file list or raw payload is loaded into
// memory. The same capability-bound check is registered with the shared read
// session so mode, symlink, file, Git, and repository-root replacement drift
// is rejected immediately before output becomes visible.
func admitRawNginxCompatibilityHostability(ctx context.Context, cfg *config.Config, canonical *state.Store, carrier config.Repo, projection config.YUMCompatibilityProjection, txDir string, values commonFlags, session *localReadAdmission) error {
	if ctx == nil || cfg == nil || canonical == nil || txDir == "" || session == nil || session.root == nil {
		return errors.New("raw compatibility hostability admission is unavailable")
	}
	baselineRef, err := state.RepoRef(carrier.ID)
	if err != nil {
		return err
	}
	baselineCommit, exists, err := canonical.Ref(baselineRef)
	if err != nil || !exists || baselineCommit.IsZero() {
		return errors.Join(err, fmt.Errorf("raw compatibility baseline ref %s is unavailable", baselineRef))
	}
	manifestPath := filepath.ToSlash(filepath.Join("manifests", carrier.ID+".tsv"))
	check := func(parent string) error {
		checkDir, err := os.MkdirTemp(parent, "sow-nginx-raw-hostability-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(checkDir)
		return validateRawNginxCompatibilityClosure(ctx, canonical, baselineCommit, manifestPath, projection.Root, session.rootPath, session.root, checkDir, values)
	}
	if err := check(txDir); err != nil {
		return err
	}
	recheck := func() error {
		// The stage-audit scratch directory belongs to
		// admittedNginxCompatibilityWithSession and is intentionally removed
		// before the outer render reaches session.Verify.  Allocate every
		// replay independently so the final proof never captures that shorter
		// lifetime.
		return check("")
	}
	// The registered pass repeats the complete unfiltered public-prefix scan,
	// worker permission closure and trailing byte scan so an excluded/additional
	// route or same-path replacement cannot appear between stage admission and
	// output.
	session.rechecks = append(session.rechecks, recheck)
	return nil
}

// validateRawNginxCompatibilityClosure validates the path Nginx actually
// aliases, not merely the carrier's include/exclude selection. Any additional
// file below the raw public prefix is therefore a manifest diff and cannot leak
// just because a local repository filter would have skipped it. The trailing
// scan closes the interval in which worker-permission checks open each path.
func validateRawNginxCompatibilityClosure(ctx context.Context, canonical *state.Store, commit plumbing.Hash, manifestPath, routeRoot, repositoryPath string, root *os.Root, tempDir string, values commonFlags) error {
	if tempDir == "" {
		return errors.New("raw compatibility closure scratch is unavailable")
	}
	expectedPath := filepath.Join(tempDir, "expected.tsv")
	if err := writeRawNginxCompatibilityExpectedManifest(canonical, commit, manifestPath, routeRoot, expectedPath); err != nil {
		return err
	}
	scan := func(name string) error {
		actualPath := filepath.Join(tempDir, name)
		if _, err := manifest.ScanRoot(ctx, root, manifest.Scope{Path: routeRoot}, actualPath, manifest.ScanOptions{
			Workers: values.workers, ChunkEntries: values.chunk, TempDir: tempDir,
		}); err != nil {
			return err
		}
		expected, err := os.Open(expectedPath)
		if err != nil {
			return err
		}
		actual, err := os.Open(actualPath)
		if err != nil {
			_ = expected.Close()
			return err
		}
		diff, diffErr := manifest.Diff(expected, actual, nil)
		closeErr := errors.Join(expected.Close(), actual.Close())
		if diffErr != nil || closeErr != nil || !diff.Clean() {
			return errors.Join(diffErr, closeErr, fmt.Errorf("raw compatibility tree changed after stage audit: added=%d removed=%d changed=%d", diff.Added, diff.Removed, diff.Changed))
		}
		return nil
	}
	if err := scan("actual-before.tsv"); err != nil {
		return err
	}
	if err := validateRawNginxCompatibilityHostability(ctx, canonical, commit, manifestPath, routeRoot, repositoryPath, root); err != nil {
		return err
	}
	if err := scan("actual-after.tsv"); err != nil {
		return err
	}
	return nil
}

// writeRawNginxCompatibilityExpectedManifest projects one compatibility root
// from the carrier-wide S0 manifest. A single inactive carrier may own both
// architecture leaves; comparing either leaf with the unfiltered carrier
// manifest would incorrectly report every sibling-architecture entry as
// removed. The projected stream preserves canonical ordering and identities.
func writeRawNginxCompatibilityExpectedManifest(canonical *state.Store, commit plumbing.Hash, manifestPath, routeRoot, destination string) (resultErr error) {
	if canonical == nil || commit.IsZero() || routeRoot == "" || destination == "" {
		return errors.New("raw compatibility expected-manifest dependencies are unavailable")
	}
	source, err := canonical.OpenPathAt(commit, manifestPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(destination)
		}
		resultErr = errors.Join(resultErr, output.Close())
	}()
	prefix := routeRoot + "/"
	stream := manifest.NewReader(source)
	var entries int64
	for {
		entry, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if !strings.HasPrefix(entry.Path, prefix) {
			continue
		}
		if err := manifest.WriteEntry(output, entry); err != nil {
			return err
		}
		entries++
	}
	if entries == 0 {
		return fmt.Errorf("raw compatibility route %s is absent from carrier baseline", routeRoot)
	}
	if err := output.Sync(); err != nil {
		return err
	}
	committed = true
	return nil
}

func validateRawNginxCompatibilityHostability(ctx context.Context, canonical *state.Store, commit plumbing.Hash, manifestPath, routeRoot, repositoryPath string, root *os.Root) (resultErr error) {
	if ctx == nil || canonical == nil || commit.IsZero() || root == nil {
		return errors.New("raw compatibility hostability dependencies are unavailable")
	}
	if err := serving.ValidateWorkerTraversableAbsoluteDirectory(repositoryPath); err != nil {
		return fmt.Errorf("repository path is not traversable by the Nginx worker: %w", err)
	}
	if err := serving.ValidateWorkerTraversableDirectoryRoot(root, routeRoot); err != nil {
		return fmt.Errorf("raw route root %s is not traversable by the Nginx worker: %w", routeRoot, err)
	}
	reader, err := canonical.OpenPathAt(commit, manifestPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, reader.Close()) }()
	stream := manifest.NewReader(reader)
	prefix := routeRoot + "/"
	var files int64
	for {
		entry, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !strings.HasPrefix(entry.Path, prefix) {
			continue
		}
		files++
	}
	if files == 0 {
		return fmt.Errorf("raw compatibility route %s has an empty baseline", routeRoot)
	}
	// Walk the complete physical alias prefix as well as the canonical file
	// list. This admits empty directories only when the Nginx worker can cross
	// them and rejects non-regular/symlink coordinates even when repository
	// selection filters would otherwise omit those paths.
	return fs.WalkDir(root.FS(), filepath.FromSlash(routeRoot), func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := root.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("raw route coordinate %s is unsafe", filepath.ToSlash(name)))
		}
		if info.IsDir() {
			if err := serving.ValidateWorkerTraversableDirectoryRoot(root, name); err != nil {
				return fmt.Errorf("raw route directory %s is not traversable by the Nginx worker: %w", filepath.ToSlash(name), err)
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("raw route coordinate %s is not a regular file", filepath.ToSlash(name))
		}
		if err := serving.ValidateWorkerReadableFileRoot(root, name); err != nil {
			return fmt.Errorf("raw route file %s is not readable by the Nginx worker: %w", filepath.ToSlash(name), err)
		}
		return nil
	})
}

// validateActiveNginxCompatibilityClosure is read-only. It proves that the
// active S3 ledger has been materialized into the exact target-partitioned
// generation/channel, mirrorlist and two frozen trust hardlinks that the
// generated Nginx and edge contracts are about to expose.
func validateActiveNginxCompatibilityClosure(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, projection config.YUMCompatibilityProjection, targetRoot, txDir string, values commonFlags) error {
	return validateActiveNginxCompatibilityClosureWithBinding(ctx, cfg, canonical, pool, projection, targetRoot, txDir, values, nil)
}

func validateActiveNginxCompatibilityClosureWithBinding(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, projection config.YUMCompatibilityProjection, targetRoot, txDir string, values commonFlags, binding *yumCompatibilityReadBinding) error {
	evidence, err := loadFrozenYUMCompatibilityServingEvidence(cfg, canonical, projection)
	if err != nil {
		return err
	}
	baseURL, err := cfg.ServingBaseURL("latest")
	if err != nil {
		return err
	}
	target, err := localServingTargetIdentity(cfg, "latest", targetRoot, baseURL)
	if err != nil {
		return err
	}
	targetBody, err := target.Canonical("latest")
	if err != nil {
		return err
	}
	if err := requireCanonicalServingTarget(canonical, target, targetBody); err != nil {
		return fmt.Errorf("canonical compatibility serving target is unavailable: %w", err)
	}
	coordinate := serving.Generation{View: "latest", Repo: projection.ID, OS: "cross-el", Arch: projection.Source.Arch}
	channel, err := readLocalServingChannel(canonical, coordinate, target)
	if err != nil || channel == nil {
		return errors.Join(err, errors.New("active compatibility channel is missing"))
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return err
	}
	if channel.TargetID != target.ID || channel.TargetRoot != target.Root || channel.BaseURL != target.BaseURL ||
		channel.View != "latest" || channel.Repo != projection.ID || channel.OS != "cross-el" || channel.Arch != projection.Source.Arch ||
		channel.LegacyRoot != projection.Root || channel.RefCommit != evidence.freezeCommit.String() || channel.ConfigSHA256 != configSHA ||
		channel.RepositoryKeySHA256 != evidence.receipt.RepositoryKeySHA256 {
		return errors.New("active compatibility channel differs from frozen S3 identity")
	}
	generationPath := serving.GenerationStatePathFor(channel.Generation, channel.View, channel.Repo, channel.OS, channel.Arch)
	generationBody, exists, err := readOptionalCanonical(canonical, generationPath)
	if err != nil || !exists {
		return errors.Join(err, errors.New("active compatibility generation record is missing"))
	}
	generation, err := serving.DecodeGeneration(generationBody)
	if err != nil {
		return err
	}
	if generation.ID != channel.Generation || generation.ContentSHA256 != channel.ContentSHA256 || generation.ManifestSHA256 != channel.ManifestSHA256 ||
		generation.View != channel.View || generation.Repo != channel.Repo || generation.OS != channel.OS || generation.Arch != channel.Arch ||
		generation.LegacyRoot != channel.LegacyRoot || generation.RefCommit != channel.RefCommit || generation.ConfigSHA256 != channel.ConfigSHA256 ||
		generation.RepositoryKeySHA256 != channel.RepositoryKeySHA256 {
		return errors.New("active compatibility channel differs from immutable generation")
	}
	manifestPath := filepath.Join(txDir, "nginx-compat-generation-"+projection.ID+".tsv")
	exists, err = stageCanonicalServingManifest(canonical, generation, manifestPath)
	if err != nil || !exists {
		return errors.Join(err, errors.New("active compatibility generation manifest is missing"))
	}
	if err := requireExistingCanonicalServingGeneration(canonical, generation, manifestPath); err != nil {
		return err
	}
	installOptions := serving.InstallOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: txDir}
	if binding == nil {
		err = serving.ValidateInstalledGeneration(ctx, pool, targetRoot, generation, manifestPath, installOptions)
	} else {
		err = serving.ValidateInstalledGenerationRoot(ctx, pool, binding.repositoryRoot, generation, manifestPath, installOptions)
	}
	if err != nil {
		return fmt.Errorf("installed compatibility generation differs: %w", err)
	}
	var mirrorBody []byte
	var mirrorExists bool
	if binding == nil {
		mirrorBody, mirrorExists, err = serving.ReadMirrorlist(targetRoot, channel.MirrorlistPath)
	} else {
		mirrorBody, mirrorExists, err = serving.ReadMirrorlistRoot(binding.repositoryRoot, channel.MirrorlistPath)
	}
	if err != nil || !mirrorExists {
		return errors.Join(err, errors.New("active compatibility mirrorlist is missing"))
	}
	wantMirror, err := channel.MirrorlistBody()
	if err != nil || !bytes.Equal(mirrorBody, wantMirror) {
		return errors.Join(err, errors.New("active compatibility mirrorlist differs from channel"))
	}
	if binding == nil {
		err = serving.ValidateMirrorlistPermissions(targetRoot, channel.MirrorlistPath)
	} else {
		err = serving.ValidateMirrorlistPermissionsRoot(binding.repositoryRoot, channel.MirrorlistPath)
	}
	if err != nil {
		return fmt.Errorf("active compatibility mirrorlist is not directly hostable: %w", err)
	}
	if binding == nil {
		err = validateInstalledFrozenYUMCompatibilityTrust(ctx, pool, targetRoot, evidence)
	} else {
		err = validateInstalledFrozenYUMCompatibilityTrustAtRoot(ctx, pool, binding.repositoryRoot, evidence)
	}
	if err != nil {
		return fmt.Errorf("active compatibility frozen trust differs: %w", err)
	}
	return nil
}

func validateNginxIncludeTrust(cfg *config.Config, repos []config.Repo, viewName string) error {
	keyrings, packageSelected, err := selectedNginxIncludeTrust(cfg, repos, viewName)
	if err != nil {
		return err
	}
	for _, keyring := range keyrings {
		if _, _, err := loadRPMPackageKeyring(cfg.Path, keyring); err != nil {
			return fmt.Errorf("RPM package keyring %s: %w", keyring, err)
		}
	}
	if !packageSelected {
		return nil
	}
	if _, _, err := loadRepositoryPublicTrustAnchor(cfg.Path, cfg.GPG.PublicKey); err != nil {
		return fmt.Errorf("repository public key: %w", err)
	}
	return nil
}

func validateNginxIncludeTrustWithSession(cfg *config.Config, repos []config.Repo, viewName string, session *localReadAdmission) error {
	if session == nil {
		return errors.New("Nginx trust read admission is unavailable")
	}
	keyrings, packageSelected, err := selectedNginxIncludeTrust(cfg, repos, viewName)
	if err != nil {
		return err
	}
	for _, keyringPath := range keyrings {
		body, err := session.ReadFile(cfg.Path, keyringPath, "RPM package keyring "+keyringPath, maxSecretBytes)
		if err != nil {
			return err
		}
		if _, err := yumrepo.ParseRPMPackageKeyring(body); err != nil {
			return fmt.Errorf("RPM package keyring %s contains no usable public OpenPGP trust history: %w", keyringPath, err)
		}
	}
	if !packageSelected {
		return nil
	}
	body, err := session.ReadFile(cfg.Path, cfg.GPG.PublicKey, "repository public key", maxSecretBytes)
	if err != nil {
		return err
	}
	if _, _, err := parseRepositoryPublicTrustAnchor(body); err != nil {
		return fmt.Errorf("repository public key: %w", err)
	}
	return nil
}

func selectedNginxIncludeTrust(cfg *config.Config, repos []config.Repo, viewName string) ([]string, bool, error) {
	view, exists := cfg.Views[viewName]
	if !exists {
		return nil, false, fmt.Errorf("view %q is not configured", viewName)
	}
	packageSelected := false
	seenYUMKeyrings := make(map[string]struct{})
	var keyrings []string
	for _, repo := range repos {
		if !repo.IsActive() || !viewIncludesRepo(view, repo.ID) {
			continue
		}
		switch repo.Type {
		case "apt":
			packageSelected = true
		case "yum":
			packageSelected = true
			if repo.YUM == nil || repo.YUM.PackageKeyring == "" {
				return nil, false, fmt.Errorf("repo %s has no public RPM package keyring", repo.ID)
			}
			if _, duplicate := seenYUMKeyrings[repo.YUM.PackageKeyring]; duplicate {
				continue
			}
			seenYUMKeyrings[repo.YUM.PackageKeyring] = struct{}{}
			keyrings = append(keyrings, repo.YUM.PackageKeyring)
		}
	}
	sort.Strings(keyrings)
	if !packageSelected {
		return keyrings, false, nil
	}
	if cfg.GPG.PublicKey == "" {
		return nil, false, errors.New("gpg.public_key is required for selected package repositories")
	}
	return keyrings, true, nil
}

func writeNginxIncludeAtomically(cfg *config.Config, targetRoot, outputPath string, body []byte) error {
	return writeNginxIncludeAtomicallyWithHook(cfg, targetRoot, outputPath, body, nil)
}

func writeNginxIncludeAtomicallyWithHook(cfg *config.Config, targetRoot, outputPath string, body []byte, beforeRename func()) (resultErr error) {
	return writeNginxIncludeAtomicallyWithBarrier(cfg, targetRoot, outputPath, body, beforeRename, nil)
}

func writeNginxIncludeAtomicallyWithBarrier(cfg *config.Config, targetRoot, outputPath string, body []byte, beforeRename func(), barrier func() error) (resultErr error) {
	if outputPath == "" || !filepath.IsAbs(outputPath) || strings.ContainsAny(outputPath, "\x00\r\n") {
		return errors.New("--nginx-include must be '-' or an absolute path")
	}
	requestedDestination := filepath.Clean(outputPath)
	if info, err := os.Lstat(requestedDestination); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("Nginx include destination is not an exact regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	requestedDirectory := filepath.Dir(requestedDestination)
	directoryInfo, err := os.Lstat(requestedDirectory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("Nginx include parent must be an existing real directory"))
	}
	resolvedDirectory, err := filepath.EvalSymlinks(requestedDirectory)
	if err != nil {
		return fmt.Errorf("resolve Nginx include parent: %w", err)
	}
	destination := filepath.Join(resolvedDirectory, filepath.Base(requestedDestination))
	if info, statErr := os.Lstat(requestedDestination); statErr == nil {
		resolvedDestination, resolveErr := filepath.EvalSymlinks(requestedDestination)
		if resolveErr != nil || resolvedDestination != destination || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.Join(resolveErr, errors.New("Nginx include destination is not an exact regular file in the resolved parent"))
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	repositoryRoot, err := resolveNginxPathPrefix(cfg.Root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	servedRoot, err := resolveNginxPathPrefix(targetRoot)
	if err != nil {
		return fmt.Errorf("resolve served tree: %w", err)
	}
	if pathsOverlap(destination, repositoryRoot) || pathsOverlap(destination, servedRoot) {
		return errors.New("Nginx include must be outside the repository and served tree")
	}
	if cfg.Path != "" {
		configPath, resolveErr := resolveNginxPathPrefix(cfg.Path)
		if resolveErr != nil {
			return fmt.Errorf("resolve active configuration: %w", resolveErr)
		}
		if pathsOverlap(destination, configPath) {
			return errors.New("Nginx include must not replace the active configuration")
		}
	}
	parent, err := os.Open(resolvedDirectory)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, parent.Close()) }()
	openedInfo, err := parent.Stat()
	if err != nil || !openedInfo.IsDir() || !os.SameFile(directoryInfo, openedInfo) {
		return errors.Join(err, errors.New("Nginx include parent changed while opening"))
	}
	// Record the resolved target inode for the pre-rename swap check.
	resolvedInfo, err := os.Stat(resolvedDirectory)
	if err != nil || !os.SameFile(resolvedInfo, openedInfo) {
		return errors.Join(err, errors.New("Nginx include resolved parent changed while opening"))
	}
	temporary, temporaryName, err := createNginxIncludeTemp(parent)
	if err != nil {
		return err
	}
	renamed := false
	closed := false
	defer func() {
		if !renamed {
			if !closed {
				resultErr = errors.Join(resultErr, temporary.Close())
			}
			resultErr = errors.Join(resultErr, unix.Unlinkat(int(parent.Fd()), temporaryName, 0))
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	closed = true
	if beforeRename != nil {
		beforeRename()
	}
	if barrier != nil {
		if err := barrier(); err != nil {
			return fmt.Errorf("Nginx include pre-commit admission: %w", err)
		}
	}
	currentDirectory, err := filepath.EvalSymlinks(requestedDirectory)
	if err != nil || currentDirectory != resolvedDirectory {
		return errors.Join(err, errors.New("Nginx include parent path changed before rename"))
	}
	currentInfo, err := os.Stat(resolvedDirectory)
	if err != nil || !os.SameFile(currentInfo, openedInfo) {
		return errors.Join(err, errors.New("Nginx include parent inode changed before rename"))
	}
	destinationBase := filepath.Base(destination)
	destinationExists, err := nginxIncludeDestinationExists(parent, destinationBase)
	if err != nil {
		return err
	}
	var generatedStat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), temporaryName, &generatedStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat generated Nginx include: %w", err)
	}
	priorRetained := false
	if destinationExists {
		if err := exchangeNginxIncludeFiles(parent.Fd(), temporaryName, destinationBase); err != nil {
			return fmt.Errorf("atomically exchange Nginx include: %w", err)
		}
		// The old destination now occupies temporaryName. Never remove it from
		// a deferred cleanup path: rollback must either exchange it back or
		// deliberately retain it as recovery evidence.
		priorRetained = true
		renamed = true
	} else {
		if err := renameNginxIncludeNoReplace(parent.Fd(), temporaryName, destinationBase); err != nil {
			return fmt.Errorf("atomically install Nginx include: %w", err)
		}
		renamed = true
	}
	rollback := func(cause error) error {
		recoveryPath := filepath.Join(resolvedDirectory, temporaryName)
		if err := verifyNginxIncludeObject(parent, destinationBase, generatedStat, body); err != nil {
			if priorRetained {
				return errors.Join(cause, fmt.Errorf("Nginx include rollback refused because installed object changed; prior include retained at %s: %w", recoveryPath, err))
			}
			return errors.Join(cause, fmt.Errorf("Nginx include rollback refused because installed object changed: %w", err))
		}
		var rollbackErr error
		if priorRetained {
			rollbackErr = exchangeNginxIncludeFiles(parent.Fd(), temporaryName, destinationBase)
			if rollbackErr != nil {
				return errors.Join(cause, fmt.Errorf("restore prior Nginx include failed; prior include retained at %s: %w", recoveryPath, rollbackErr), parent.Sync())
			}
			priorRetained = false
			rollbackErr = unix.Unlinkat(int(parent.Fd()), temporaryName, 0)
		} else {
			rollbackErr = unix.Unlinkat(int(parent.Fd()), destinationBase, 0)
		}
		return errors.Join(cause, rollbackErr, parent.Sync())
	}
	if err := parent.Sync(); err != nil {
		if barrier != nil {
			return rollback(err)
		}
		return err
	}
	if barrier != nil {
		if err := barrier(); err != nil {
			return rollback(fmt.Errorf("Nginx include post-commit admission: %w", err))
		}
	}
	if err := verifyNginxIncludeParent(requestedDirectory, resolvedDirectory, openedInfo); err != nil {
		return rollback(fmt.Errorf("Nginx include post-commit parent admission: %w", err))
	}
	if err := verifyNginxIncludeObject(parent, destinationBase, generatedStat, body); err != nil {
		return rollback(fmt.Errorf("Nginx include post-commit object admission: %w", err))
	}
	if priorRetained {
		if err := unix.Unlinkat(int(parent.Fd()), temporaryName, 0); err != nil {
			return fmt.Errorf("remove retained prior Nginx include: %w", err)
		}
		priorRetained = false
		if err := parent.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func nginxIncludeDestinationExists(parent *os.File, destination string) (bool, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), destination, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("stat Nginx include destination: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return false, errors.New("Nginx include destination is not an exact regular file")
	}
	return true, nil
}

func verifyNginxIncludeParent(requestedDirectory, resolvedDirectory string, openedInfo os.FileInfo) error {
	currentDirectory, err := filepath.EvalSymlinks(requestedDirectory)
	if err != nil || currentDirectory != resolvedDirectory {
		return errors.Join(err, errors.New("Nginx include parent path changed"))
	}
	currentInfo, err := os.Stat(resolvedDirectory)
	if err != nil || !os.SameFile(currentInfo, openedInfo) {
		return errors.Join(err, errors.New("Nginx include parent inode changed"))
	}
	return nil
}

func verifyNginxIncludeObject(parent *os.File, destination string, expected unix.Stat_t, body []byte) (resultErr error) {
	fd, err := unix.Openat(int(parent.Fd()), destination, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	object := os.NewFile(uintptr(fd), destination)
	defer func() { resultErr = errors.Join(resultErr, object.Close()) }()
	var actual unix.Stat_t
	if err := unix.Fstat(fd, &actual); err != nil {
		return err
	}
	if actual.Mode&unix.S_IFMT != unix.S_IFREG || actual.Dev != expected.Dev || actual.Ino != expected.Ino {
		return errors.New("Nginx include object identity changed")
	}
	actualBody, err := io.ReadAll(io.LimitReader(object, int64(len(body))+1))
	if err != nil {
		return err
	}
	if !bytes.Equal(actualBody, body) {
		return errors.New("Nginx include object content changed")
	}
	return nil
}

func createNginxIncludeTemp(parent *os.File) (*os.File, string, error) {
	for attempt := 0; attempt < 128; attempt++ {
		random := make([]byte, 12)
		if _, err := io.ReadFull(cryptorand.Reader, random); err != nil {
			return nil, "", err
		}
		name := ".sow-nginx-" + hex.EncodeToString(random) + ".tmp"
		fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return os.NewFile(uintptr(fd), name), name, nil
	}
	return nil, "", errors.New("could not allocate a unique Nginx include temporary file")
}

func resolveNginxPathPrefix(value string) (string, error) {
	if value == "" || !filepath.IsAbs(value) || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("path must be a non-empty absolute path without control characters")
	}
	candidate := filepath.Clean(value)
	missing := make([]string, 0, 4)
	for {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", err
		}
		missing = append(missing, filepath.Base(candidate))
		candidate = parent
	}
}
