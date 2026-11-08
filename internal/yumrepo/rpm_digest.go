package yumrepo

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"

	crpm "github.com/cavaliergopher/rpm"
)

// VerifyPackageDigests checks embedded RPM checksums before an older package is
// discarded. This detects damaged bytes; it does not establish signer trust.
// Both the main header and payload must be covered by supported checksums.
func VerifyPackageDigests(ctx context.Context, r io.ReadSeeker) (resultErr error) {
	if ctx == nil || r == nil {
		return fmt.Errorf("%w: nil RPM digest input", ErrInvalidPackage)
	}
	offset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	defer func() {
		if _, err := r.Seek(offset, io.SeekStart); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return err
	}
	pkg, err := crpm.Read(&contextReader{ctx: ctx, r: r})
	if err != nil {
		return err
	}
	start, end := pkg.HeaderRange()
	fileEnd, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if end <= start || int64(end) > fileEnd {
		return fmt.Errorf("%w: invalid RPM header range", ErrInvalidPackage)
	}
	headerOK, payloadOK := false, false
	if pkg.Signature.GetTag(1004) != nil { // Legacy MD5 covers main header and payload.
		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := crpm.MD5Check(&contextReader{ctx: ctx, r: r}); err != nil {
			return fmt.Errorf("%w: RPM MD5 digest: %w", ErrInvalidPackage, err)
		}
		headerOK, payloadOK = true, true
	}
	for _, check := range []struct {
		tag     int
		newHash func() hash.Hash
	}{{269, sha1.New}, {273, sha256.New}} {
		tag := pkg.Signature.GetTag(check.tag)
		if tag == nil {
			continue
		}
		h := check.newHash()
		if _, err := r.Seek(int64(start), io.SeekStart); err != nil {
			return err
		}
		if _, err := io.CopyN(h, &contextReader{ctx: ctx, r: r}, int64(end-start)); err != nil {
			return err
		}
		if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(tag.String()) {
			return fmt.Errorf("%w: RPM header digest tag %d mismatch", ErrInvalidPackage, check.tag)
		}
		headerOK = true
	}
	// RPM v6 writes PAYLOADSHA256 without the algorithm tag that v4 requires.
	// Name the unsupported format instead of reporting algorithm 0.
	if pkg.Header.GetTag(rpmTagPayloadDigest) != nil && pkg.Header.GetTag(rpmTagPayloadDigestAlgo) == nil {
		return fmt.Errorf("%w: RPM v6 packages are not supported (payload digest has no algorithm tag)", ErrInvalidPackage)
	}
	if pkg.Header.GetTag(rpmTagPayloadDigest) != nil || pkg.Header.GetTag(rpmTagPayloadDigestAlgo) != nil {
		layout := rpmVerificationLayout{
			mainHeaderStart: int64(start), mainHeaderEnd: int64(end), fileEnd: fileEnd,
			payloadDigests:  pkg.Header.GetTag(rpmTagPayloadDigest).StringSlice(),
			payloadHashAlgo: int(pkg.Header.GetTag(rpmTagPayloadDigestAlgo).Int64()),
		}
		if _, _, err := verifySignedRPMPayloadDigest(ctx, r, layout); err != nil {
			return fmt.Errorf("%w: RPM payload digest: %w", ErrInvalidPackage, err)
		}
		payloadOK = true
	}
	if !headerOK || !payloadOK {
		return fmt.Errorf("%w: RPM lacks supported header and payload digests", ErrInvalidPackage)
	}
	return ctx.Err()
}
