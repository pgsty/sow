package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
	"github.com/pgsty/sow/internal/yumrepo"
)

type physicalPayloadIdentity struct {
	Device    uint64
	Inode     uint64
	Size      int64
	MTimeNano int64
	CTimeNano int64
}

func physicalPayloadIdentityFrom(identity rootedRegularIdentity) physicalPayloadIdentity {
	return physicalPayloadIdentity{
		Device: identity.device, Inode: identity.inode, Size: identity.size,
		MTimeNano: identity.modUnixNano, CTimeNano: identity.changeUnixNano,
	}
}

type checkPayloadEvidence struct {
	Identity          rootedRegularIdentity
	File              state.GenerationFile
	Object            state.PackageObject
	RPMFacts          *yumrepo.PackageFacts
	DEBFacts          *aptrepo.Package
	RPMNeutralSHA256  string
	StructuralSigner  string
	SignatureResults  map[string]yumrepo.RPMSignatureTrustRingResult
	SignatureAuditErr error
}

type payloadEvidenceSlot struct {
	done     chan struct{}
	evidence *checkPayloadEvidence
	err      error
}

type payloadEvidenceRegistry struct {
	mu    sync.Mutex
	slots map[physicalPayloadIdentity]*payloadEvidenceSlot
}

func newPayloadEvidenceRegistry() *payloadEvidenceRegistry {
	return &payloadEvidenceRegistry{slots: make(map[physicalPayloadIdentity]*payloadEvidenceSlot)}
}

type checkVerificationSnapshot struct {
	Public   *publicGenerationSnapshot
	Evidence *payloadEvidenceRegistry
}

type checkRPMTrustPlan struct {
	Rings       []yumrepo.RPMSignatureTrustRing
	Retained    map[string]map[string]string
	CurrentRing string
	TrustedRing string
}

func buildCheckRPMTrustPlan(retained retainedRPMKeyrings, policy rpmSigningPolicy) checkRPMTrustPlan {
	plan := checkRPMTrustPlan{Retained: make(map[string]map[string]string)}
	byIdentity := make(map[string]yumrepo.RPMSignatureTrustRing)
	for fingerprint, snapshots := range retained {
		plan.Retained[fingerprint] = make(map[string]string, len(snapshots))
		for snapshot, keyring := range snapshots {
			identity := "retained/" + fingerprint + "/" + snapshot
			plan.Retained[fingerprint][snapshot] = identity
			byIdentity[identity] = yumrepo.RPMSignatureTrustRing{Identity: identity, Keyring: keyring}
		}
	}
	if policy.current != nil {
		plan.CurrentRing = "policy/current/" + policy.currentPrint + "/" + policy.currentSnapshot
		byIdentity[plan.CurrentRing] = yumrepo.RPMSignatureTrustRing{Identity: plan.CurrentRing, Keyring: policy.current}
	}
	if policy.trusted != nil {
		identityMaterial := strings.Join(policy.trustedPrint, ",") + "\n" + strings.Join(policy.trustedSnapshots, ",")
		plan.TrustedRing = "policy/trusted/" + bytesSHA([]byte(identityMaterial))
		byIdentity[plan.TrustedRing] = yumrepo.RPMSignatureTrustRing{Identity: plan.TrustedRing, Keyring: policy.trusted}
	}
	identities := make([]string, 0, len(byIdentity))
	for identity := range byIdentity {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	for _, identity := range identities {
		plan.Rings = append(plan.Rings, byIdentity[identity])
	}
	return plan
}

func (registry *payloadEvidenceRegistry) auditObject(ctx context.Context, source ManagedPackageSource, object state.PackageObject, stored *state.PackageFact, trust checkRPMTrustPlan, observedAt time.Time) (*checkPayloadEvidence, error) {
	opened, err := source.open()
	if err != nil {
		return nil, err
	}
	before, err := snapshotRootedRegularIdentity(opened)
	if err != nil {
		return nil, errors.Join(err, opened.CloseVerified())
	}
	key := physicalPayloadIdentityFrom(before)
	slot, owner := registry.claim(key)
	if !owner {
		<-slot.done
		closeErr := opened.CloseVerified()
		if slot.err != nil || closeErr != nil {
			return nil, errors.Join(slot.err, closeErr)
		}
		if slot.evidence == nil || !slot.evidence.Identity.unchangedWhileOpen(before) || slot.evidence.File.Size != object.Size || slot.evidence.File.SHA256 != object.SHA256 {
			return nil, fmt.Errorf("%w: physical payload evidence conflicts with package object %s", ErrIntegrity, object.SHA256)
		}
		return slot.evidence, nil
	}
	evidence, auditErr := auditOpenedPackageEvidence(ctx, opened, before, source, object, stored, trust, observedAt)
	registry.complete(key, slot, evidence, auditErr)
	return evidence, auditErr
}

func auditOpenedPackageEvidence(ctx context.Context, opened *rootedRegularFile, before rootedRegularIdentity, source ManagedPackageSource, object state.PackageObject, stored *state.PackageFact, trust checkRPMTrustPlan, observedAt time.Time) (*checkPayloadEvidence, error) {
	digest, neutral, err := authenticatePackageDescriptor(ctx, opened.file, object)
	if err != nil || digest != object.SHA256 || object.Format == "rpm" && neutral != object.PayloadSHA256 {
		return nil, errors.Join(fmt.Errorf("%w: package %s checksum or RPM-neutral identity differs", ErrIntegrity, object.SHA256), err, opened.CloseVerified())
	}
	evidence := &checkPayloadEvidence{
		Identity: before, File: state.GenerationFile{Path: object.PoolPath, Phase: "payload", Size: object.Size, SHA256: digest},
		Object: object, RPMNeutralSHA256: neutral, SignatureResults: make(map[string]yumrepo.RPMSignatureTrustRingResult),
	}
	decoded := ManagedPackageSource{}
	if stored != nil && !stored.Corrupt {
		decoded, err = decodeManagedPackageFact(source, *stored)
	}
	if err != nil || stored == nil || stored.Corrupt {
		decoded, err = inspectKnownPackageFacts(ctx, opened.file, source)
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%w: package %s facts differ from SQLite/bytes", ErrIntegrity, object.SHA256), err, opened.CloseVerified())
	}
	evidence.RPMFacts, evidence.DEBFacts = decoded.RPMFacts, decoded.DEBFacts
	if object.Format == "rpm" {
		evidence.StructuralSigner, err = inspectStructuralRPMKeyIDReader(ctx, opened.file)
		if err == nil && evidence.StructuralSigner != "" && len(trust.Rings) != 0 {
			var results []yumrepo.RPMSignatureTrustRingResult
			results, evidence.SignatureAuditErr = yumrepo.VerifyEmbeddedRPMSignaturesMulti(ctx, opened.file, trust.Rings, observedAt)
			for _, result := range results {
				evidence.SignatureResults[result.Identity] = result
			}
		}
		if err != nil {
			evidence.SignatureAuditErr = err
		}
	}
	after, identityErr := snapshotRootedRegularIdentity(opened)
	closeErr := opened.CloseVerified()
	if identityErr != nil || closeErr != nil || !before.unchangedWhileOpen(after) {
		return nil, errors.Join(fmt.Errorf("%w: package descriptor identity changed during audit", ErrIntegrity), identityErr, closeErr)
	}
	return evidence, nil
}

func inspectKnownPackageFacts(ctx context.Context, reader *os.File, source ManagedPackageSource) (ManagedPackageSource, error) {
	object := source.Object
	switch object.Format {
	case "rpm":
		facts, info, err := yumrepo.InspectManagedPackageFactsReaderKnown(ctx, reader, object.Filename, object.SHA256, object.Size)
		actual, objectErr := rpmObjectFromInfo(info, object.Filename, object.PayloadSHA256)
		if err != nil || objectErr != nil || !sameManagedPackageFacts(object, actual) {
			return ManagedPackageSource{}, errors.Join(err, objectErr, errors.New("known RPM facts differ from immutable object"))
		}
		source.RPMFacts, source.DEBFacts = facts, nil
		return source, nil
	case "deb":
		facts, err := aptrepo.InspectPackageReaderKnown(ctx, reader, "main", object.Filename, object.SHA256, object.Size)
		facts.SourcePath = source.Path
		actual, objectErr := debObjectFromInfo(facts, object.Filename)
		if err != nil || objectErr != nil || !sameManagedPackageFacts(object, actual) {
			return ManagedPackageSource{}, errors.Join(err, objectErr, errors.New("known DEB facts differ from immutable object"))
		}
		source.DEBFacts, source.RPMFacts = &facts, nil
		return source, nil
	default:
		return ManagedPackageSource{}, errors.New("unsupported package object format")
	}
}

func authenticatePackageDescriptor(ctx context.Context, reader *os.File, object state.PackageObject) (string, string, error) {
	neutralOffset := int64(-1)
	if object.Format == "rpm" {
		var err error
		neutralOffset, err = yumrepo.RPMSignatureNeutralOffset(ctx, reader)
		if err != nil {
			return "", "", err
		}
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return "", "", err
	}
	fullHash := sha256.New()
	neutralHash := sha256.New()
	buffer := make([]byte, 128<<10)
	position, total := int64(0), int64(0)
	for {
		n, err := (&managedContextReader{ctx: ctx, reader: reader}).Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			_, _ = fullHash.Write(chunk)
			if neutralOffset >= 0 && position+int64(n) > neutralOffset {
				start := max(int64(0), neutralOffset-position)
				_, _ = neutralHash.Write(chunk[start:])
			}
			position += int64(n)
			total += int64(n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", "", err
		}
	}
	workmetrics.RecordFullPackageRead(workmetrics.WithPhase(ctx, "check_authenticity"), total)
	if total != object.Size {
		return "", "", fmt.Errorf("read %d bytes, want %d", total, object.Size)
	}
	neutral := ""
	if neutralOffset >= 0 {
		neutral = hex.EncodeToString(neutralHash.Sum(nil))
	}
	return hex.EncodeToString(fullHash.Sum(nil)), neutral, nil
}

func (registry *payloadEvidenceRegistry) verifyRetainedReference(ctx context.Context, root string, file state.GenerationFile) error {
	opened, err := openRootedRegular(root, filepath.FromSlash(strings.TrimPrefix(file.Path, "/")))
	if err != nil {
		return fmt.Errorf("%w: retained source %q is missing or unsafe: %v", ErrIntegrity, file.Path, err)
	}
	identity, err := snapshotRootedRegularIdentity(opened)
	if err != nil {
		return errors.Join(err, opened.CloseVerified())
	}
	key := physicalPayloadIdentityFrom(identity)
	slot, owner := registry.claim(key)
	if !owner {
		<-slot.done
		closeErr := opened.CloseVerified()
		if slot.err != nil || closeErr != nil || slot.evidence == nil || !slot.evidence.Identity.unchangedWhileOpen(identity) || slot.evidence.File.Size != file.Size || slot.evidence.File.SHA256 != file.SHA256 {
			return errors.Join(fmt.Errorf("%w: retained payload evidence differs for %q", ErrIntegrity, file.Path), slot.err, closeErr)
		}
		return nil
	}
	if _, err := opened.file.Seek(0, io.SeekStart); err != nil {
		registry.complete(key, slot, nil, errors.Join(err, opened.CloseVerified()))
		return slot.err
	}
	hash := sha256.New()
	read, copyErr := io.Copy(hash, &retainedContextReader{ctx: ctx, reader: opened.file})
	workmetrics.RecordFullPackageRead(workmetrics.WithPhase(ctx, "retained_payload"), read)
	after, identityErr := snapshotRootedRegularIdentity(opened)
	closeErr := opened.CloseVerified()
	if copyErr != nil || identityErr != nil || closeErr != nil || !identity.unchangedWhileOpen(after) || read != file.Size || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		err = errors.Join(fmt.Errorf("%w: retained source %q differs from manifest", ErrIntegrity, file.Path), copyErr, identityErr, closeErr)
		registry.complete(key, slot, nil, err)
		return err
	}
	evidence := &checkPayloadEvidence{Identity: identity, File: file, SignatureResults: make(map[string]yumrepo.RPMSignatureTrustRingResult)}
	registry.complete(key, slot, evidence, nil)
	return nil
}

func (registry *payloadEvidenceRegistry) walkedPayload(ctx context.Context, file *os.File, info os.FileInfo, relative string) (state.GenerationFile, error) {
	identity, err := snapshotRegularDescriptorIdentity(file)
	if err != nil {
		return state.GenerationFile{}, err
	}
	key := physicalPayloadIdentityFrom(identity)
	registry.mu.Lock()
	slot := registry.slots[key]
	registry.mu.Unlock()
	if slot != nil {
		<-slot.done
		if slot.err != nil || slot.evidence == nil || !slot.evidence.Identity.unchangedWhileOpen(identity) {
			return state.GenerationFile{}, errors.Join(fmt.Errorf("%w: public payload evidence is invalid for %s", ErrIntegrity, relative), slot.err)
		}
		return state.GenerationFile{Path: relative, Phase: "payload", Size: slot.evidence.File.Size, SHA256: slot.evidence.File.SHA256}, nil
	}
	hash := sha256.New()
	read, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: file})
	workmetrics.RecordFullPackageRead(workmetrics.WithPhase(ctx, "public_payload_reaudit"), read)
	after, identityErr := snapshotRegularDescriptorIdentity(file)
	if err != nil || identityErr != nil || !identity.unchangedWhileOpen(after) || read != info.Size() {
		return state.GenerationFile{}, errors.Join(fmt.Errorf("%w: public payload changed while re-auditing %s", ErrIntegrity, relative), err, identityErr)
	}
	result := state.GenerationFile{Path: relative, Phase: "payload", Size: read, SHA256: hex.EncodeToString(hash.Sum(nil))}
	registry.mu.Lock()
	registry.slots[key] = &payloadEvidenceSlot{done: closedEvidenceChannel(), evidence: &checkPayloadEvidence{Identity: identity, File: result, SignatureResults: make(map[string]yumrepo.RPMSignatureTrustRingResult)}}
	registry.mu.Unlock()
	return result, nil
}

func closedEvidenceChannel() chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func (registry *payloadEvidenceRegistry) claim(key physicalPayloadIdentity) (*payloadEvidenceSlot, bool) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if slot := registry.slots[key]; slot != nil {
		return slot, false
	}
	slot := &payloadEvidenceSlot{done: make(chan struct{})}
	registry.slots[key] = slot
	return slot, true
}

func (registry *payloadEvidenceRegistry) complete(key physicalPayloadIdentity, slot *payloadEvidenceSlot, evidence *checkPayloadEvidence, err error) {
	registry.mu.Lock()
	if registry.slots[key] == slot {
		slot.evidence, slot.err = evidence, err
		close(slot.done)
	}
	registry.mu.Unlock()
}

func checkRingVerified(evidence *checkPayloadEvidence, identity string) bool {
	if evidence == nil || identity == "" || evidence.SignatureAuditErr != nil {
		return false
	}
	result, ok := evidence.SignatureResults[identity]
	return ok && result.Verified
}

func validateStoredRPMEvidence(object state.PackageObject, evidence *checkPayloadEvidence, trust checkRPMTrustPlan) error {
	if evidence == nil {
		return errors.New("package authentication evidence is unavailable")
	}
	identity := strings.ToUpper(object.SignatureKey)
	if len(identity) == 40 || len(identity) == 64 {
		for _, ringIdentity := range trust.Retained[identity] {
			if checkRingVerified(evidence, ringIdentity) {
				return nil
			}
		}
		return fmt.Errorf("package is not verified by its retained signer %s", identity)
	}
	if evidence.SignatureAuditErr != nil {
		return evidence.SignatureAuditErr
	}
	if strings.ToUpper(evidence.StructuralSigner) != identity {
		return fmt.Errorf("structural signature identity %q differs from stored identity %q", evidence.StructuralSigner, object.SignatureKey)
	}
	return nil
}

func authorizeDesiredRPMEvidence(policy rpmSigningPolicy, evidence *checkPayloadEvidence, trust checkRPMTrustPlan) error {
	switch policy.mode {
	case "never":
		return nil
	case "fill":
		if !checkRingVerified(evidence, trust.TrustedRing) {
			return errors.New("package is not verified by the configured trusted keys")
		}
		return nil
	case "always":
		if !checkRingVerified(evidence, trust.CurrentRing) {
			return errors.New("package is not verified by the configured current key")
		}
		return nil
	default:
		return fmt.Errorf("unsupported package signing mode %q", policy.mode)
	}
}

func validateBuiltRPMAuthorizationEvidence(object state.PackageObject, evidence *checkPayloadEvidence, signing config.EffectiveRPMPackageSigningConfig, trust checkRPMTrustPlan) error {
	if signing.Mode == "" || signing.Mode == "never" {
		return validateStoredRPMEvidence(object, evidence, trust)
	}
	allowed := map[string]map[string]struct{}{}
	if signing.Mode == "always" {
		allowed[strings.ToUpper(signing.KeyFingerprint)] = map[string]struct{}{signing.KeySnapshotSHA256: {}}
	} else if signing.Mode == "fill" {
		for _, fingerprint := range signing.TrustedKeyFingerprints {
			allowed[strings.ToUpper(fingerprint)] = map[string]struct{}{}
		}
		for _, snapshot := range signing.TrustedKeySnapshotSHA256s {
			for fingerprint, rings := range trust.Retained {
				if _, ok := allowed[fingerprint]; ok {
					if _, exists := rings[snapshot]; exists {
						allowed[fingerprint][snapshot] = struct{}{}
					}
				}
			}
		}
	} else {
		return fmt.Errorf("unknown retained RPM package signing mode %q", signing.Mode)
	}
	for fingerprint, snapshots := range allowed {
		for snapshot := range snapshots {
			if checkRingVerified(evidence, trust.Retained[fingerprint][snapshot]) {
				return nil
			}
		}
	}
	return fmt.Errorf("package is not verified by the retained %s authorization", signing.Mode)
}
