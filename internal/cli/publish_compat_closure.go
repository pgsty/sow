package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

// validateCommittedCompatibilityPublicationClosure locates the immutable
// canonical state that first recorded this generation. This is intentionally
// separate from mutable HEAD validation: L2 must prove the committed
// content.tsv and plan closed over the exact frozen candidate at publication
// time, not merely that today's refs still point at plausible evidence.
func validateCommittedCompatibilityPublicationClosure(canonical *state.Store, target string, generation pub.TargetGeneration, plan pub.Plan) error {
	if len(generation.Compatibility) == 0 {
		return nil
	}
	commit, recorded, err := targetGenerationPublicationState(canonical, target, generation.Generation)
	if err != nil {
		return err
	}
	want, err := generation.Canonical()
	if err != nil {
		return err
	}
	got, err := recorded.Canonical()
	if err != nil || !bytes.Equal(got, want) {
		return errors.Join(err, fmt.Errorf("target %s generation %d canonical publication state differs from verification state", target, generation.Generation))
	}
	return validateHistoricalCompatibilityPublicationClosure(canonical, commit, generation, plan)
}

// validateHistoricalCompatibilityPublicationClosure is the L2 read-side gate
// for frozen cross-EL roots. content.tsv must contain exactly the frozen S2
// candidate under each route root. Whenever that channel was advanced by this
// generation, the persisted plan must also contain the complete payload,
// immutable metadata, raw alias pair and independent mirrorlist route.
func validateHistoricalCompatibilityPublicationClosure(canonical *state.Store, commit plumbing.Hash, generation pub.TargetGeneration, plan pub.Plan) error {
	for _, identity := range generation.Compatibility {
		candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(identity.ID)
		candidateBlob, exists, err := canonical.BlobIdentityAt(commit, candidatePath)
		if err != nil || !exists || candidateBlob.Hash.String() != identity.CandidateManifestGit || candidateBlob.Size != identity.CandidateManifestSize {
			return errors.Join(err, fmt.Errorf("compatibility %s candidate manifest Git identity differs from generation", identity.ID))
		}
		candidateSHA, exists, err := hashCanonicalPathOptionalAt(canonical, commit, candidatePath)
		if err != nil || !exists || candidateSHA != identity.CandidateManifestSHA256 {
			return errors.Join(err, fmt.Errorf("compatibility %s candidate manifest SHA-256 differs from generation", identity.ID))
		}
		receiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(identity.ID)
		receiptBlob, exists, err := canonical.BlobIdentityAt(commit, receiptPath)
		if err != nil || !exists || receiptBlob.Hash.String() != identity.CandidateReceiptGit || receiptBlob.Size != identity.CandidateReceiptSize {
			return errors.Join(err, fmt.Errorf("compatibility %s candidate receipt Git identity differs from generation", identity.ID))
		}
		receiptBody, exists, err := readCanonicalBytesAt(canonical, commit, receiptPath, maximumYUMCompatibilityWitnessBytes)
		if err != nil || !exists || int64(len(receiptBody)) != identity.CandidateReceiptSize || digestBytesCLI(receiptBody) != identity.CandidateReceiptSHA256 {
			return errors.Join(err, fmt.Errorf("compatibility %s candidate receipt bytes differ from generation", identity.ID))
		}
		receipt, err := decodeYUMCompatibilityCandidate(receiptBody)
		if err != nil || receipt.ID != identity.ID || receipt.Root != identity.Root || receipt.Carrier != identity.Carrier || receipt.OwnerRepo != identity.OwnerRepo ||
			receipt.SourceRef != identity.SourceRef || receipt.SourceCommit != identity.SourceCommit || receipt.SourceManifestSHA256 != identity.SourceManifestSHA256 || receipt.SourceManifestGit != identity.SourceManifestGit || receipt.SourceManifestSize != identity.SourceManifestSize ||
			receipt.AdoptionSHA256 != identity.AdoptionSHA256 || receipt.AdoptionGit != identity.AdoptionGit || receipt.AdoptionSize != identity.AdoptionSize ||
			receipt.PackageTrustSHA256 != identity.PackageTrustSHA256 || receipt.PackageTrustGit != identity.PackageTrustGit || receipt.PackageTrustSize != identity.PackageTrustSize ||
			receipt.CandidateManifestSHA256 != identity.CandidateManifestSHA256 || receipt.CandidateManifestGit != identity.CandidateManifestGit || receipt.CandidateManifestSize != identity.CandidateManifestSize ||
			receipt.RepomdSHA256 != identity.RepomdSHA256 || receipt.RepositoryKeySHA256 != identity.RepositoryKeySHA256 {
			return errors.Join(err, fmt.Errorf("compatibility %s candidate receipt semantic identity differs from generation", identity.ID))
		}
		confirmation, err := yumCompatibilityConfirmation("freeze", receipt)
		if err != nil || receipt.FreezeConfirm != confirmation {
			return errors.Join(err, fmt.Errorf("compatibility %s candidate receipt confirmation is not content-bound", identity.ID))
		}
		if _, err := loadHistoricalCompatibilityTrust(canonical, commit, identity, receipt); err != nil {
			return err
		}

		candidate, err := canonical.OpenPathAt(commit, candidatePath)
		if err != nil {
			return err
		}
		payloadPath, _ := state.YUMCompatibilityManifestPath(identity.ID)
		payload, err := canonical.OpenPathAt(commit, payloadPath)
		if err != nil {
			_ = candidate.Close()
			return err
		}
		_, _, candidateErr := validateHistoricalCompatibilityCandidate(candidate, payload, identity)
		closeErr := errors.Join(candidate.Close(), payload.Close())
		if candidateErr != nil || closeErr != nil {
			return errors.Join(candidateErr, closeErr)
		}
		if err := validateCompatibilityContentRoot(canonical, commit, generation.Target, identity, candidatePath); err != nil {
			return err
		}
		channel, found := compatibilityChannel(generation, identity.ChannelRemoteKey)
		if !found {
			return fmt.Errorf("compatibility %s has no independent channel in historical generation", identity.ID)
		}
		if channel.Generation == generation.Generation {
			if err := validateCompatibilityPlanRoute(canonical, commit, generation, plan, identity, channel, candidatePath); err != nil {
				return err
			}
		} else if err := validateCompatibilityPlanRouteUnchanged(plan, identity, channel); err != nil {
			return err
		}
	}
	return nil
}

func compatibilityChannel(generation pub.TargetGeneration, remoteKey string) (pub.ChannelState, bool) {
	for _, channel := range generation.Channels {
		if channel.RemoteKey == remoteKey {
			return channel, true
		}
	}
	return pub.ChannelState{}, false
}

func validateCompatibilityContentRoot(canonical *state.Store, commit plumbing.Hash, target pub.TargetName, identity pub.CompatibilityState, candidatePath string) error {
	content, err := canonical.OpenPathAt(commit, remoteStatePath(string(target), "content.tsv"))
	if err != nil {
		return err
	}
	candidate, err := canonical.OpenPathAt(commit, candidatePath)
	if err != nil {
		_ = content.Close()
		return err
	}
	contentReader := manifest.NewReader(content)
	candidateReader := manifest.NewReader(candidate)
	candidateEntry, candidateErr := candidateReader.Next()
	for {
		entry, readErr := contentReader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = content.Close()
			_ = candidate.Close()
			return readErr
		}
		relative, inRoot := pathBelowRoot(entry.Path, identity.RouteRoot)
		if !inRoot {
			continue
		}
		if candidateErr != nil {
			_ = content.Close()
			_ = candidate.Close()
			if errors.Is(candidateErr, io.EOF) {
				return fmt.Errorf("historical content has extra compatibility path %s", entry.Path)
			}
			return candidateErr
		}
		want := candidateEntry
		want.Path = path.Join(identity.RouteRoot, candidateEntry.Path)
		if entry != want || relative != candidateEntry.Path {
			_ = content.Close()
			_ = candidate.Close()
			return fmt.Errorf("historical compatibility content entry %s differs from frozen candidate %s", entry.Path, want.Path)
		}
		candidateEntry, candidateErr = candidateReader.Next()
	}
	closeErr := errors.Join(content.Close(), candidate.Close())
	if candidateErr != nil && !errors.Is(candidateErr, io.EOF) {
		return errors.Join(candidateErr, closeErr)
	}
	if !errors.Is(candidateErr, io.EOF) {
		return errors.Join(fmt.Errorf("historical content omits frozen compatibility path %s", path.Join(identity.RouteRoot, candidateEntry.Path)), closeErr)
	}
	return closeErr
}

type compatibilityExpectedObject struct {
	size         int64
	sha256       string
	class        pub.ObjectClass
	allowAdopted bool
	cdnPath      string
}

type compatibilityFrozenTrustObject struct {
	canonicalPath string
	remotePath    string
	size          int64
	sha256        string
}

// loadHistoricalCompatibilityTrust binds both public trust URLs to the exact
// packet bytes preserved by the S2 freeze. Package trust is also recorded in
// CompatibilityState; repository trust is deliberately recovered from the
// content-bound candidate receipt so a mutable current config key can never
// substitute for the signer that produced the frozen repomd.xml.asc.
func loadHistoricalCompatibilityTrust(canonical *state.Store, commit plumbing.Hash, identity pub.CompatibilityState, receipt yumCompatibilityCandidate) ([]compatibilityFrozenTrustObject, error) {
	if receipt.PackageTrustSHA256 != identity.PackageTrustSHA256 || receipt.PackageTrustGit != identity.PackageTrustGit || receipt.PackageTrustSize != identity.PackageTrustSize ||
		receipt.RepositoryKeySHA256 != identity.RepositoryKeySHA256 {
		return nil, fmt.Errorf("compatibility %s trust receipt differs from generation", identity.ID)
	}
	type trustIdentity struct {
		canonicalPath string
		remotePath    string
		sha256        string
		git           string
		size          int64
	}
	packagePath, _ := state.YUMCompatibilityPackageTrustPath(identity.ID)
	repositoryPath, _ := state.YUMCompatibilityRepositoryTrustPath(identity.ID)
	items := []trustIdentity{
		{canonicalPath: packagePath, remotePath: config.YUMCompatibilityPackageTrustRoute(identity.ID), sha256: receipt.PackageTrustSHA256, git: receipt.PackageTrustGit, size: receipt.PackageTrustSize},
		{canonicalPath: repositoryPath, remotePath: config.YUMCompatibilityRepositoryTrustRoute(identity.ID), sha256: receipt.RepositoryTrustSHA256, git: receipt.RepositoryTrustGit, size: receipt.RepositoryTrustSize},
	}
	result := make([]compatibilityFrozenTrustObject, 0, len(items))
	var repositoryBody []byte
	for _, item := range items {
		body, exists, err := readCanonicalBytesAt(canonical, commit, item.canonicalPath, maxSecretBytes)
		if err != nil || !exists || int64(len(body)) != item.size || digestBytesCLI(body) != item.sha256 {
			return nil, errors.Join(err, fmt.Errorf("compatibility %s frozen trust bytes %s differ from receipt", identity.ID, item.canonicalPath))
		}
		blob, exists, err := canonical.BlobIdentityAt(commit, item.canonicalPath)
		if err != nil || !exists || blob.Hash.String() != item.git || blob.Size != item.size {
			return nil, errors.Join(err, fmt.Errorf("compatibility %s frozen trust Git identity %s differs from receipt", identity.ID, item.canonicalPath))
		}
		if item.canonicalPath == repositoryPath {
			repositoryBody = body
		}
		result = append(result, compatibilityFrozenTrustObject{canonicalPath: item.canonicalPath, remotePath: item.remotePath, size: item.size, sha256: item.sha256})
	}
	if repositoryTrustAnchorDigest(repositoryBody) != identity.RepositoryKeySHA256 {
		return nil, fmt.Errorf("compatibility %s frozen repository trust differs from signed metadata identity", identity.ID)
	}
	return result, nil
}

func validateCompatibilityPlanRoute(canonical *state.Store, commit plumbing.Hash, generation pub.TargetGeneration, plan pub.Plan, identity pub.CompatibilityState, channel pub.ChannelState, candidatePath string) error {
	expected := make(map[string]compatibilityExpectedObject)
	receiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(identity.ID)
	receiptBody, exists, err := readCanonicalBytesAt(canonical, commit, receiptPath, maximumYUMCompatibilityWitnessBytes)
	if err != nil || !exists {
		return errors.Join(err, fmt.Errorf("compatibility %s candidate receipt is unavailable for trust closure", identity.ID))
	}
	receipt, err := decodeYUMCompatibilityCandidate(receiptBody)
	if err != nil {
		return err
	}
	trust, err := loadHistoricalCompatibilityTrust(canonical, commit, identity, receipt)
	if err != nil {
		return err
	}
	for _, item := range trust {
		expected[item.remotePath] = compatibilityExpectedObject{size: item.size, sha256: item.sha256, class: pub.ObjectImmutable, cdnPath: item.remotePath}
	}
	candidate, err := canonical.OpenPathAt(commit, candidatePath)
	if err != nil {
		return err
	}
	reader := manifest.NewReader(candidate)
	generationID := fmt.Sprintf("%020d", generation.Generation)
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = candidate.Close()
			return readErr
		}
		remotePath := path.Join(identity.RouteRoot, entry.Path)
		if strings.HasPrefix(entry.Path, "repodata/") {
			generationKey := path.Join(".sow/generations", generationID, "yum", remotePath)
			expected[generationKey] = compatibilityExpectedObject{size: entry.Size, sha256: entry.HashString(), class: pub.ObjectMetadata, cdnPath: path.Join("_sow/v1/g", generationID, remotePath)}
			aliasClass := pub.ObjectYUMAliasMetadata
			if entry.Path == "repodata/repomd.xml" || entry.Path == "repodata/repomd.xml.asc" {
				aliasClass = pub.ObjectYUMAliasPointer
			}
			expected[remotePath] = compatibilityExpectedObject{size: entry.Size, sha256: entry.HashString(), class: aliasClass, cdnPath: remotePath}
			continue
		}
		expected[remotePath] = compatibilityExpectedObject{size: entry.Size, sha256: entry.HashString(), class: pub.ObjectImmutable, allowAdopted: true, cdnPath: remotePath}
	}
	if closeErr := candidate.Close(); closeErr != nil {
		return closeErr
	}
	pointerKey, pointerBody, err := pub.YUMChannelPointer(plan.CDNBaseURL, channel)
	if err != nil {
		return err
	}
	expected[pointerKey] = compatibilityExpectedObject{size: int64(len(pointerBody)), sha256: digestBytesCLI(pointerBody), class: pub.ObjectPointer, cdnPath: pointerKey}
	for _, deletion := range plan.Deletes {
		if compatibilityDeleteTouchesRoute(deletion, identity, channel) {
			return fmt.Errorf("compatibility plan deletes routed object %s", deletion.RemoteKey)
		}
	}

	seen := make(map[string]struct{}, len(expected))
	verify := make(map[string]pub.VerifyObject, len(plan.Verify))
	for _, item := range plan.Verify {
		if _, duplicate := verify[item.URL]; duplicate {
			return fmt.Errorf("compatibility plan has duplicate verification URL %s", item.URL)
		}
		verify[item.URL] = item
	}
	for _, object := range plan.Objects {
		want, wanted := expected[object.RemoteKey]
		trustRoot := path.Dir(config.YUMCompatibilityPackageTrustRoute(identity.ID))
		inRoute := object.RemoteKey == pointerKey || strings.HasPrefix(object.RemoteKey, identity.RouteRoot+"/") || strings.HasPrefix(object.RemoteKey, trustRoot+"/") || strings.HasPrefix(object.RemoteKey, path.Join(".sow/generations", generationID, "yum", identity.RouteRoot)+"/")
		if !wanted {
			if inRoute {
				return fmt.Errorf("compatibility plan has extra routed object %s", object.RemoteKey)
			}
			continue
		}
		if _, duplicate := seen[object.RemoteKey]; duplicate {
			return fmt.Errorf("compatibility plan duplicates routed object %s", object.RemoteKey)
		}
		seen[object.RemoteKey] = struct{}{}
		classOK := object.Class == want.class || want.allowAdopted && object.Class == pub.ObjectAdoptedImmutable
		if !classOK || object.Size != want.size || object.SHA256 != want.sha256 || object.CDNPath != want.cdnPath {
			return fmt.Errorf("compatibility plan object %s differs from frozen routed candidate", object.RemoteKey)
		}
		url := strings.TrimSuffix(plan.CDNBaseURL, "/") + "/" + strings.TrimPrefix(want.cdnPath, "/")
		verification, exists := verify[url]
		if !exists || verification.Size != want.size || verification.SHA256 != want.sha256 {
			return fmt.Errorf("compatibility plan object %s lacks exact CDN verification", object.RemoteKey)
		}
	}
	if len(seen) != len(expected) {
		missing := make([]string, 0, len(expected)-len(seen))
		for remoteKey := range expected {
			if _, exists := seen[remoteKey]; !exists {
				missing = append(missing, remoteKey)
			}
		}
		sort.Strings(missing)
		return fmt.Errorf("compatibility plan omits routed objects: %s", strings.Join(missing, ","))
	}
	expectedPurges := make(map[string]struct{}, 3)
	base, err := url.Parse(plan.CDNBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return errors.Join(err, errors.New("rollback plan has no canonical HTTPS CDN base"))
	}
	planURL := func(key string) string {
		joined := *base
		joined.Path = path.Join(base.Path, key)
		joined.RawPath = ""
		return joined.String()
	}
	for remoteKey, object := range expected {
		if object.class != pub.ObjectPointer && object.class != pub.ObjectYUMAliasPointer {
			continue
		}
		cdnPath := object.cdnPath
		if cdnPath == "" {
			cdnPath = remoteKey
		}
		expectedPurges[planURL(cdnPath)] = struct{}{}
	}
	seenPurges := make(map[string]struct{}, len(expectedPurges))
	for _, purgeURL := range plan.PurgeURLs {
		touches, err := compatibilityPurgeTouchesRoute(plan, purgeURL, identity, channel)
		if err != nil {
			return err
		}
		if !touches {
			continue
		}
		if _, expected := expectedPurges[purgeURL]; !expected {
			return fmt.Errorf("compatibility plan has extra routed purge %s", purgeURL)
		}
		seenPurges[purgeURL] = struct{}{}
	}
	if len(seenPurges) != len(expectedPurges) {
		return fmt.Errorf("compatibility plan purge closure covers %d of %d routed pointers", len(seenPurges), len(expectedPurges))
	}
	return nil
}

// validateDesiredCompatibilityPublicationPlan is the final write-side gate
// after CDN verify/purge expansion and before the plan is persisted or any
// remote object is touched.
func validateDesiredCompatibilityPublicationPlan(canonical *state.Store, commit plumbing.Hash, generation pub.TargetGeneration, plan pub.Plan) error {
	for _, identity := range generation.Compatibility {
		channel, found := compatibilityChannel(generation, identity.ChannelRemoteKey)
		if !found {
			return fmt.Errorf("compatibility %s has no independent desired channel", identity.ID)
		}
		if channel.Generation != generation.Generation {
			if err := validateCompatibilityPlanRouteUnchanged(plan, identity, channel); err != nil {
				return err
			}
			continue
		}
		candidatePath, _ := state.YUMCompatibilityCandidateManifestPath(identity.ID)
		if err := validateCompatibilityPlanRoute(canonical, commit, generation, plan, identity, channel, candidatePath); err != nil {
			return err
		}
	}
	return nil
}

// validateCompatibilityPlanRouteUnchanged makes carry-forward compatibility
// state a true no-op for its independently owned route. A publication for an
// unrelated view/repository may retain the channel vector, but it cannot hide
// writes, deletes, or purges below that frozen root in its change set.
func validateCompatibilityPlanRouteUnchanged(plan pub.Plan, identity pub.CompatibilityState, channel pub.ChannelState) error {
	for _, object := range plan.Objects {
		if compatibilityRemoteKeyTouchesRoute(object.RemoteKey, identity, channel) {
			return fmt.Errorf("carried compatibility %s unexpectedly writes routed object %s", identity.ID, object.RemoteKey)
		}
	}
	for _, deletion := range plan.Deletes {
		if compatibilityDeleteTouchesRoute(deletion, identity, channel) {
			return fmt.Errorf("carried compatibility %s unexpectedly deletes routed object %s", identity.ID, deletion.RemoteKey)
		}
	}
	for _, purgeURL := range plan.PurgeURLs {
		touches, err := compatibilityPurgeTouchesRoute(plan, purgeURL, identity, channel)
		if err != nil {
			return err
		}
		if touches {
			return fmt.Errorf("carried compatibility %s unexpectedly purges routed URL %s", identity.ID, purgeURL)
		}
	}
	return nil
}

// augmentRolledBackCompatibilityDeletes turns an append-only local rollback
// into an evidence-bound remote fail-closed transition. The desired manifest
// has already exact-replaced the raw route with verified S0 bytes. Every
// candidate-only raw path plus mirrorlist/trust is removed; immutable
// generation archives and unrelated routes remain available for recovery.
func augmentRolledBackCompatibilityDeletes(canonical *state.Store, target string, prepared preparedPublication, parent *pub.TargetGeneration, oldManifestPath string, plan *pub.Plan) error {
	if len(prepared.compatibilityRollbacks) == 0 {
		return nil
	}
	if canonical == nil || parent == nil || plan == nil || oldManifestPath == "" || prepared.view != "latest" || prepared.restoreSourceGeneration != 0 {
		return fmt.Errorf("%w: compatibility rollback deletion has no ordinary latest parent closure", pub.ErrDrift)
	}
	existingDeletes := make(map[string]struct{}, len(plan.Deletes))
	for _, deletion := range plan.Deletes {
		existingDeletes[deletion.RemoteKey] = struct{}{}
	}
	var deletions []pub.PlannedDelete
	for id, identity := range prepared.compatibilityRollbacks {
		if id != identity.ID {
			return fmt.Errorf("%w: compatibility rollback identity map changed", pub.ErrDrift)
		}
		channel, found := compatibilityChannel(*parent, identity.ChannelRemoteKey)
		if !found || channel.Generation == 0 || channel.View != "latest" || channel.Repo != id || channel.OS != "cross-el" {
			return fmt.Errorf("%w: compatibility rollback %s has no exact parent channel", pub.ErrDrift, id)
		}
		commit, generation, err := targetGenerationPublicationState(canonical, target, channel.Generation)
		if err != nil {
			return fmt.Errorf("%w: locate compatibility rollback %s generation: %v", pub.ErrDrift, id, err)
		}
		closure, exists, err := loadHistoricalPublicationClosureAt(canonical, target, commit)
		if err != nil || !exists || closure.generation.Generation != generation.Generation {
			return errors.Join(err, fmt.Errorf("%w: compatibility rollback %s lacks a complete historical publication closure", pub.ErrDrift, id))
		}
		if err := validateHistoricalCompatibilityPublicationClosure(canonical, commit, closure.generation, closure.plan); err != nil {
			return fmt.Errorf("%w: compatibility rollback %s parent closure: %v", pub.ErrDrift, id, err)
		}
		rawRemoved, err := compatibilityRollbackRemovedEntries(oldManifestPath, identity.RouteRoot, plan.Removed)
		if err != nil {
			return fmt.Errorf("%w: compatibility rollback %s removed raw closure: %v", pub.ErrDrift, id, err)
		}
		routeDeletes, err := rolledBackCompatibilityRouteDeletes(id, identity, channel, closure.plan.Objects, rawRemoved, existingDeletes)
		if err != nil {
			return err
		}
		deletions = append(deletions, routeDeletes...)
	}
	sort.Slice(deletions, func(i, j int) bool { return deletions[i].RemoteKey < deletions[j].RemoteKey })
	plan.Deletes = append(plan.Deletes, deletions...)
	return nil
}

// rolledBackCompatibilityRouteDeletes derives the complete public revocation
// set from the previously audited S3 plan and the exact old-manifest diff.
func rolledBackCompatibilityRouteDeletes(id string, identity pub.CompatibilityState, channel pub.ChannelState, objects []pub.PlannedObject, rawRemoved map[string]manifest.Entry, existingDeletes map[string]struct{}) ([]pub.PlannedDelete, error) {
	mirrorKey := path.Join("_sow/v1/mirrorlist", "latest", channel.Repo, channel.OS, channel.Arch+".txt")
	packageTrust := config.YUMCompatibilityPackageTrustRoute(id)
	repositoryTrust := config.YUMCompatibilityRepositoryTrustRoute(id)
	required := map[string]bool{mirrorKey: false, packageTrust: false, repositoryTrust: false}
	for key := range rawRemoved {
		required[key] = false
	}
	seen := make(map[string]struct{})
	var deletions []pub.PlannedDelete
	for _, object := range objects {
		deleteObject := false
		switch {
		case object.RemoteKey == mirrorKey:
			deleteObject = object.Class == pub.ObjectPointer && object.CDNPath == mirrorKey
		case object.RemoteKey == packageTrust || object.RemoteKey == repositoryTrust:
			deleteObject = object.Class == pub.ObjectImmutable && object.CDNPath == object.RemoteKey
		case rawRemoved[object.RemoteKey].Path != "":
			entry := rawRemoved[object.RemoteKey]
			relative, inRoute := pathBelowRoot(object.RemoteKey, identity.RouteRoot)
			allowedShape := inRoute && (strings.HasPrefix(relative, "Packages/") || strings.HasPrefix(relative, "repodata/"))
			allowedClass := object.Class == pub.ObjectImmutable || object.Class == pub.ObjectAdoptedImmutable ||
				object.Class == pub.ObjectYUMAliasMetadata || object.Class == pub.ObjectYUMAliasPointer
			deleteObject = allowedShape && allowedClass && object.CDNPath == object.RemoteKey && object.Size == entry.Size && object.SHA256 == entry.HashString()
		}
		if !deleteObject {
			continue
		}
		if _, duplicate := seen[object.RemoteKey]; duplicate {
			return nil, fmt.Errorf("%w: compatibility rollback %s has duplicate serving evidence %s", pub.ErrDrift, id, object.RemoteKey)
		}
		seen[object.RemoteKey] = struct{}{}
		if _, duplicate := existingDeletes[object.RemoteKey]; duplicate {
			return nil, fmt.Errorf("%w: compatibility rollback %s duplicates planned deletion %s", pub.ErrDrift, id, object.RemoteKey)
		}
		required[object.RemoteKey] = true
		deletions = append(deletions, pub.PlannedDelete{
			Class: pub.DeleteCompatibilityServing, SourcePath: object.RemoteKey, RemoteKey: object.RemoteKey,
			Size: object.Size, SHA256: object.SHA256, CDNPath: object.CDNPath,
		})
	}
	for key, found := range required {
		if !found {
			return nil, fmt.Errorf("%w: compatibility rollback %s parent closure omits %s", pub.ErrDrift, id, key)
		}
	}
	return deletions, nil
}

// compatibilityRollbackRemovedEntries resolves only the O(change-set) raw
// removals against the exact old target manifest. A path outside Packages or
// repodata is never silently promoted to deletion authority.
func compatibilityRollbackRemovedEntries(oldManifestPath, routeRoot string, removed []string) (map[string]manifest.Entry, error) {
	wanted := make(map[string]struct{})
	for _, removedPath := range removed {
		relative, inRoute := pathBelowRoot(removedPath, routeRoot)
		if !inRoute {
			continue
		}
		if !strings.HasPrefix(relative, "Packages/") && !strings.HasPrefix(relative, "repodata/") {
			return nil, fmt.Errorf("raw rollback removal %s is outside candidate Packages/repodata", removedPath)
		}
		wanted[removedPath] = struct{}{}
	}
	result := make(map[string]manifest.Entry, len(wanted))
	if len(wanted) == 0 {
		return result, nil
	}
	file, err := os.Open(oldManifestPath)
	if err != nil {
		return nil, err
	}
	reader := manifest.NewReader(file)
	for {
		entry, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			_ = file.Close()
			return nil, nextErr
		}
		if _, exists := wanted[entry.Path]; exists {
			result[entry.Path] = entry
		}
	}
	if closeErr := file.Close(); closeErr != nil {
		return nil, closeErr
	}
	if len(result) != len(wanted) {
		return nil, fmt.Errorf("old manifest proves %d of %d raw rollback removals", len(result), len(wanted))
	}
	return result, nil
}

// validateRolledBackCompatibilityPublicationPlan is the final post-CDN gate.
// It proves that the plan's positive and negative closures are a bijection
// with the exact S0 route transition before the plan is persisted.
func validateRolledBackCompatibilityPublicationPlan(prepared preparedPublication, plan pub.Plan) error {
	if len(prepared.compatibilityRollbacks) == 0 {
		return nil
	}
	base, err := url.Parse(plan.CDNBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return errors.Join(err, errors.New("rollback plan has no canonical HTTPS CDN base"))
	}
	planURL := func(key string) string {
		joined := *base
		joined.Path = path.Join(base.Path, key)
		joined.RawPath = ""
		return joined.String()
	}
	verify := make(map[string]pub.VerifyObject, len(plan.Verify))
	for _, expectation := range plan.Verify {
		verify[expectation.URL] = expectation
	}
	absent := make(map[string]struct{}, len(plan.VerifyAbsent))
	for _, expectation := range plan.VerifyAbsent {
		absent[expectation.URL] = struct{}{}
	}
	purges := make(map[string]struct{}, len(plan.PurgeURLs))
	for _, rawURL := range plan.PurgeURLs {
		purges[rawURL] = struct{}{}
	}
	deletes := make(map[string]pub.PlannedDelete)
	for _, deletion := range plan.Deletes {
		deletes[deletion.RemoteKey] = deletion
	}
	allowedCompatibilityDeletes := make(map[string]struct{})
	for id, identity := range prepared.compatibilityRollbacks {
		channel := pub.ChannelState{View: "latest", Repo: id, OS: "cross-el"}
		for _, projection := range prepared.projections {
			if projection.isYUMCompatibilityRollback() && projection.compatibilityID == id {
				channel.Arch = projection.arch
			}
		}
		if channel.Arch == "" {
			return fmt.Errorf("rollback %s has no exact S0 projection", id)
		}
		expectedDeletes := map[string]struct{}{
			path.Join("_sow/v1/mirrorlist", "latest", id, "cross-el", channel.Arch+".txt"): {},
			config.YUMCompatibilityPackageTrustRoute(id):                                   {},
			config.YUMCompatibilityRepositoryTrustRoute(id):                                {},
		}
		for _, removed := range plan.Removed {
			if _, inRoute := pathBelowRoot(removed, identity.RouteRoot); inRoute {
				expectedDeletes[removed] = struct{}{}
			}
		}
		for key := range expectedDeletes {
			allowedCompatibilityDeletes[key] = struct{}{}
			deletion, exists := deletes[key]
			if !exists || deletion.Class != pub.DeleteCompatibilityServing || deletion.CDNPath != key {
				return fmt.Errorf("rollback %s omits exact deletion %s", id, key)
			}
			rawURL := planURL(key)
			if _, exists := absent[rawURL]; !exists {
				return fmt.Errorf("rollback %s omits VerifyAbsent for %s", id, key)
			}
			if _, exists := purges[rawURL]; !exists {
				return fmt.Errorf("rollback %s omits purge for %s", id, key)
			}
		}
		for _, deletion := range plan.Deletes {
			relative, inRoute := pathBelowRoot(deletion.RemoteKey, identity.RouteRoot)
			if !inRoute {
				continue
			}
			if _, expected := expectedDeletes[deletion.RemoteKey]; !expected ||
				(!strings.HasPrefix(relative, "Packages/") && !strings.HasPrefix(relative, "repodata/")) {
				return fmt.Errorf("rollback %s has unauthorized raw deletion %s", id, deletion.RemoteKey)
			}
		}
		for _, object := range plan.Objects {
			relative, inRoute := pathBelowRoot(object.RemoteKey, identity.RouteRoot)
			if !inRoute {
				continue
			}
			wantClass := pub.ObjectCompatibilityRollbackMetadata
			switch {
			case path.Base(relative) == relative && strings.HasSuffix(relative, ".rpm"):
				wantClass = pub.ObjectImmutable
			case relative == "repodata/repomd.xml":
				wantClass = pub.ObjectCompatibilityRollbackPointer
			case strings.HasPrefix(relative, "repodata/"):
			default:
				return fmt.Errorf("rollback %s writes non-S0 path %s", id, object.RemoteKey)
			}
			if object.Class != wantClass || object.CDNPath != object.RemoteKey {
				return fmt.Errorf("rollback %s writes %s with class/path %s/%s", id, object.RemoteKey, object.Class, object.CDNPath)
			}
			expectation, exists := verify[planURL(object.RemoteKey)]
			if !exists || expectation.Size != object.Size || expectation.SHA256 != object.SHA256 {
				return fmt.Errorf("rollback %s omits exact Verify for %s", id, object.RemoteKey)
			}
		}
	}
	for _, deletion := range plan.Deletes {
		if deletion.Class != pub.DeleteCompatibilityServing {
			continue
		}
		if _, allowed := allowedCompatibilityDeletes[deletion.RemoteKey]; !allowed {
			return fmt.Errorf("compatibility rollback contains unrelated deletion %s", deletion.RemoteKey)
		}
	}
	return nil
}

func compatibilityDeleteTouchesRoute(deletion pub.PlannedDelete, identity pub.CompatibilityState, channel pub.ChannelState) bool {
	return compatibilityRemoteKeyTouchesRoute(deletion.RemoteKey, identity, channel) ||
		compatibilityRemoteKeyTouchesRoute(deletion.CDNPath, identity, channel)
}

func compatibilityRemoteKeyTouchesRoute(remoteKey string, identity pub.CompatibilityState, channel pub.ChannelState) bool {
	if remoteKey == "" {
		return false
	}
	mirrorKey := path.Join("_sow/v1/mirrorlist", "latest", channel.Repo, channel.OS, channel.Arch+".txt")
	trustRoot := path.Dir(config.YUMCompatibilityPackageTrustRoute(identity.ID))
	if remoteKey == channel.RemoteKey || remoteKey == mirrorKey || strings.HasPrefix(remoteKey, strings.TrimSuffix(identity.RouteRoot, "/")+"/") || strings.HasPrefix(remoteKey, trustRoot+"/") {
		return true
	}
	generationTail := "/yum/" + strings.Trim(identity.RouteRoot, "/") + "/"
	return (strings.HasPrefix(remoteKey, ".sow/generations/") || strings.HasPrefix(remoteKey, ".sow/gated/generations/")) && strings.Contains(remoteKey, generationTail)
}

func compatibilityPurgeTouchesRoute(plan pub.Plan, purgeURL string, identity pub.CompatibilityState, channel pub.ChannelState) (bool, error) {
	base := strings.TrimSuffix(plan.CDNBaseURL, "/") + "/"
	if !strings.HasPrefix(purgeURL, base) {
		return false, fmt.Errorf("compatibility plan purge %s is outside CDN base %s", purgeURL, plan.CDNBaseURL)
	}
	return compatibilityRemoteKeyTouchesRoute(strings.TrimPrefix(purgeURL, base), identity, channel), nil
}
