package plain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/v2/signing"
	"github.com/pgsty/sow/internal/yumrepo"
)

type fileOwnership struct {
	uid int
	gid int
}

func ownershipFromInfo(info os.FileInfo) (fileOwnership, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return fileOwnership{}, errors.New("file ownership is unavailable")
	}
	return fileOwnership{uid: int(stat.Uid), gid: int(stat.Gid)}, nil
}

func preservedFileMode(mode os.FileMode) os.FileMode {
	return mode.Perm() | mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)
}

// applyFileMetadata restores ownership before mode because chown may clear the
// setuid and setgid bits on POSIX filesystems.
func applyFileMetadata(file *os.File, source os.FileInfo) error {
	wantOwner, err := ownershipFromInfo(source)
	if err != nil {
		return err
	}
	current, err := file.Stat()
	if err != nil {
		return err
	}
	currentOwner, err := ownershipFromInfo(current)
	if err != nil {
		return err
	}
	if currentOwner != wantOwner {
		if err := file.Chown(wantOwner.uid, wantOwner.gid); err != nil && !errors.Is(err, syscall.EPERM) {
			return err
		}
	}
	return file.Chmod(preservedFileMode(source.Mode()))
}

// stageSignedRPMs applies the explicit signing policy only to private copies.
// The returned facts point at those final bytes so metadata and markers bind
// the exact packages that publication will later install.
func stageSignedRPMs(ctx context.Context, root, stage string, scan scanResult, opts Options) (scanResult, error) {
	if opts.SignWith == "" {
		return scan, nil
	}
	if !scan.hasRPM {
		if opts.Strict {
			return scanResult{}, &Error{Kind: KindRejected, Op: "sign rpm", Err: errors.New("--sign-with requires at least one retained top-level RPM package")}
		}
		scan.warnings = append(scan.warnings, "--sign-with specified but no RPM packages were retained to sign")
		return scan, nil
	}

	type group struct {
		facts []packageFact
	}
	groups := make([]group, 0)
	byDigest := make(map[string]int)
	for _, fact := range scan.kept {
		if fact.format != formatRPM {
			continue
		}
		if index, ok := byDigest[fact.originalSHA256]; ok {
			groups[index].facts = append(groups[index].facts, fact)
			continue
		}
		byDigest[fact.originalSHA256] = len(groups)
		groups = append(groups, group{facts: []packageFact{fact}})
	}

	signer := opts.SignRPM
	var signKeyring openpgp.KeyRing
	if signer == nil {
		signer = func(ctx context.Context, path, key string, overwrite bool) error {
			return signRPMWithCommand(ctx, root, path, key, overwrite)
		}
		var err error
		signKeyring, err = exportCommandSignKeyring(ctx, opts.SignWith)
		if err != nil {
			return scanResult{}, &Error{Kind: KindRuntime, Op: "export rpm signing key", Err: err}
		}
	}
	updates := make(map[string]packageFact)
	packageDir := filepath.Join(stage, "packages")
	packageDirCreated := false
	for _, current := range groups {
		representative := current.facts[0]
		needsSigning := opts.Overwrite
		if !needsSigning {
			signatures, err := embeddedRPMSignaturesAllowUnsigned(ctx, representative.originalPath)
			if err != nil {
				return scanResult{}, &Error{Kind: KindRuntime, Op: "inspect rpm signature", Path: representative.originalPath, Err: err}
			}
			needsSigning = len(signatures) == 0
		}
		if !needsSigning {
			continue
		}
		// Reject symlinked RPMs that require in-place signing upfront before
		// publication can withdraw markers or partially install outputs.
		for _, original := range current.facts {
			linfo, lerr := os.Lstat(original.originalPath)
			if lerr != nil || !linfo.Mode().IsRegular() || linfo.Mode()&os.ModeSymlink != 0 {
				return scanResult{}, &Error{Kind: KindRejected, Op: "sign rpm", Path: original.base, Err: errors.New("cannot sign symlinked or non-regular RPM in place")}
			}
		}
		if !packageDirCreated {
			if err := os.Mkdir(packageDir, 0o700); err != nil {
				return scanResult{}, &Error{Kind: KindRuntime, Op: "create signed rpm stage", Path: packageDir, Err: err}
			}
			packageDirCreated = true
		}

		neutralBefore, err := signatureNeutralDigest(ctx, representative.originalPath)
		if err != nil {
			return scanResult{}, err
		}
		signedPath := filepath.Join(packageDir, representative.base)
		if err := copyStageRPM(ctx, representative.originalPath, signedPath); err != nil {
			return scanResult{}, err
		}
		if err := signer(ctx, signedPath, opts.SignWith, opts.Overwrite); err != nil {
			return scanResult{}, &Error{Kind: KindRuntime, Op: "sign rpm", Path: representative.base, Err: err}
		}
		if err := preserveStageRPMMetadata(signedPath, representative.originalPath); err != nil {
			return scanResult{}, err
		}
		signatures, err := embeddedRPMSignatures(ctx, signedPath)
		if err != nil || len(signatures) == 0 {
			return scanResult{}, &Error{Kind: KindRuntime, Op: "verify signed rpm", Path: representative.base, Err: errors.Join(err, errors.New("signing helper did not produce a structurally valid embedded signature"))}
		}
		if signKeyring != nil {
			if err := verifyCryptographicRPMSignature(ctx, signedPath, signKeyring); err != nil {
				return scanResult{}, &Error{Kind: KindIntegrity, Op: "verify signed rpm", Path: representative.base, Err: err}
			}
		}
		neutralAfter, err := signatureNeutralDigest(ctx, signedPath)
		if err != nil {
			return scanResult{}, err
		}
		if neutralAfter != neutralBefore {
			return scanResult{}, &Error{Kind: KindIntegrity, Op: "verify signed rpm", Path: representative.base, Err: errors.New("signing helper changed the immutable RPM header or payload")}
		}

		for index, original := range current.facts {
			path := signedPath
			if index != 0 {
				path = filepath.Join(packageDir, original.base)
				if err := copyStageRPM(ctx, signedPath, path); err != nil {
					return scanResult{}, err
				}
				if err := preserveStageRPMMetadata(path, original.originalPath); err != nil {
					return scanResult{}, err
				}
			}
			final, err := inspectPackageFact(ctx, path, original.base, formatRPM, nil)
			if err != nil {
				return scanResult{}, &Error{Kind: KindRuntime, Op: "parse signed rpm", Path: original.base, Err: err}
			}
			if final.coordinate != original.coordinate || final.name != original.name || final.version != original.version || final.arch != original.arch {
				return scanResult{}, &Error{Kind: KindIntegrity, Op: "verify signed rpm", Path: original.base, Err: errors.New("signing changed the RPM logical identity")}
			}
			final.originalPath = original.originalPath
			final.originalSHA256 = original.originalSHA256
			final.sourceInfo = original.sourceInfo
			final.signed = true
			updates[original.base] = final
		}
	}
	if packageDirCreated {
		if err := syncDir(packageDir); err != nil {
			return scanResult{}, &Error{Kind: KindRuntime, Op: "sync signed rpm stage", Path: packageDir, Err: err}
		}
	}
	apply := func(facts []packageFact) {
		for index := range facts {
			if replacement, ok := updates[facts[index].base]; ok {
				facts[index] = replacement
			}
		}
	}
	apply(scan.all)
	apply(scan.index)
	apply(scan.kept)
	return scan, nil
}

func preserveStageRPMMetadata(target, original string) error {
	targetInfo, err := os.Lstat(target)
	if err != nil || !targetInfo.Mode().IsRegular() || targetInfo.Mode()&os.ModeSymlink != 0 {
		return &Error{Kind: KindRuntime, Op: "inspect rpm signing output", Path: target, Err: errors.Join(err, errors.New("output is not a regular file"))}
	}
	info, err := os.Stat(original)
	if err != nil || !info.Mode().IsRegular() {
		return &Error{Kind: KindRuntime, Op: "inspect rpm signing mode", Path: original, Err: errors.Join(err, errors.New("input is not a regular file"))}
	}
	if err := os.Chmod(target, 0o600); err != nil {
		return &Error{Kind: KindRuntime, Op: "open rpm signing output", Path: target, Err: err}
	}
	file, err := os.OpenFile(target, os.O_RDWR, 0)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "open rpm signing output", Path: target, Err: err}
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(targetInfo, opened) {
		_ = file.Close()
		return &Error{Kind: KindIntegrity, Op: "bind rpm signing output", Path: target, Err: errors.Join(statErr, errors.New("output changed while opening"))}
	}
	metadataErr := applyFileMetadata(file, info)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(metadataErr, syncErr, closeErr); err != nil {
		return &Error{Kind: KindRuntime, Op: "preserve rpm signing metadata", Path: target, Err: err}
	}
	return nil
}

func exportCommandSignKeyring(ctx context.Context, key string) (openpgp.KeyRing, error) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		return nil, errors.New("gpg executable is required for --sign-with")
	}
	command := exec.CommandContext(ctx, gpg, "--batch", "--no-tty", "--export", "0x"+key)
	command.WaitDelay = 5 * time.Second
	stderrBuf := &limitedStderrBuffer{limit: 4096}
	command.Stderr = stderrBuf
	publicKey, err := command.Output()
	if err != nil || len(publicKey) == 0 {
		if detail := stderrBuf.Summary(512); detail != "" {
			return nil, fmt.Errorf("cannot export configured OpenPGP public key from gpg: %s", detail)
		}
		return nil, errors.New("cannot export configured OpenPGP public key from gpg")
	}
	return yumrepo.ParseRPMPackageKeyring(publicKey)
}

func verifyCryptographicRPMSignature(ctx context.Context, path string, signKeyring openpgp.KeyRing) error {
	file, err := openRegularFile(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = yumrepo.VerifyEmbeddedRPMSignatures(ctx, file, signKeyring, time.Now().UTC())
	return err
}

func signatureNeutralDigest(ctx context.Context, path string) (string, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return "", &Error{Kind: KindRuntime, Op: "open rpm for signature-neutral digest", Path: path, Err: err}
	}
	digest, digestErr := yumrepo.RPMSignatureNeutralDigest(ctx, file)
	if err := errors.Join(digestErr, file.Close()); err != nil {
		return "", &Error{Kind: KindRuntime, Op: "hash signature-neutral rpm", Path: path, Err: err}
	}
	return digest, nil
}

func embeddedRPMSignaturesAllowUnsigned(ctx context.Context, path string) ([]yumrepo.EmbeddedRPMSignature, error) {
	signatures, err := embeddedRPMSignatures(ctx, path)
	if errors.Is(err, yumrepo.ErrUnsignedRPMPackage) {
		return nil, nil
	}
	return signatures, err
}

func embeddedRPMSignatures(ctx context.Context, path string) ([]yumrepo.EmbeddedRPMSignature, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return nil, err
	}
	signatures, inspectErr := yumrepo.InspectEmbeddedRPMSignatures(ctx, file)
	closeErr := file.Close()
	if errors.Is(inspectErr, yumrepo.ErrUnsignedRPMPackage) {
		if closeErr != nil {
			return nil, closeErr
		}
		return nil, inspectErr
	}
	if err := errors.Join(inspectErr, closeErr); err != nil {
		return nil, err
	}
	return signatures, nil
}

func copyStageRPM(ctx context.Context, source, target string) error {
	before, err := os.Stat(source)
	if err != nil || !before.Mode().IsRegular() {
		return &Error{Kind: KindRuntime, Op: "inspect rpm signing input", Path: source, Err: errors.Join(err, errors.New("input is not a regular file"))}
	}
	in, err := openRegularFile(source)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "open rpm signing input", Path: source, Err: err}
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "create rpm signing stage", Path: target, Err: err}
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(target)
		}
	}()
	if _, err := io.Copy(out, &contextReader{ctx: ctx, reader: in}); err != nil {
		return &Error{Kind: KindRuntime, Op: "copy rpm signing stage", Path: target, Err: err}
	}
	if err := applyFileMetadata(out, before); err != nil {
		return &Error{Kind: KindRuntime, Op: "preserve rpm signing metadata", Path: target, Err: err}
	}
	if err := errors.Join(out.Sync(), out.Close()); err != nil {
		return &Error{Kind: KindRuntime, Op: "sync rpm signing stage", Path: target, Err: err}
	}
	ok = true
	return nil
}

func signRPMWithCommand(ctx context.Context, root, path, key string, overwrite bool) error {
	rpm, err := exec.LookPath("rpm")
	if err != nil {
		return errors.New("rpm executable is required for --sign-with")
	}
	operation := "--addsign"
	if overwrite {
		operation = "--resign"
	}
	source, err := signing.Select(ctx, root, "", "")
	if err != nil {
		return err
	}
	passfile, cleanup, err := signing.RPMFile(source)
	if err != nil {
		return err
	}
	defer cleanup()
	args := []string{
		"--define", "_signature gpg",
		"--define", "_gpg_name " + key,
		"--define", "_gpg_digest_algo sha256",
	}
	if gnupgHome := os.Getenv("GNUPGHOME"); gnupgHome != "" && !strings.ContainsAny(gnupgHome, " \t\r\n%\x00\"'\\") {
		args = append(args, "--define", "_gpg_path "+gnupgHome)
	}
	args = append(args, signing.RPMArgs(passfile)...)
	args = append(args, operation, "--", path)
	command := exec.CommandContext(ctx, rpm, args...)
	command.WaitDelay = 5 * time.Second
	stderrBuf := &limitedStderrBuffer{limit: 4096}
	command.Stdout = io.Discard
	command.Stderr = stderrBuf
	if err := command.Run(); err != nil {
		detail := stderrBuf.Summary(512)
		if detail != "" {
			return fmt.Errorf("rpm %s failed: %w (%s)", operation, err, detail)
		}
		return fmt.Errorf("rpm %s failed: %w", operation, err)
	}
	return nil
}

type limitedStderrBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedStderrBuffer) Write(p []byte) (int, error) {
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
		} else {
			_, _ = b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *limitedStderrBuffer) Summary(maxRunes int) string {
	s := strings.TrimSpace(b.buf.String())
	if s == "" {
		return ""
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\ufffd")
	}
	runes := []rune(s)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes]) + "..."
	}
	return s
}
