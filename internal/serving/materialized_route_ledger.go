package serving

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/pgsty/sow/internal/manifest"
)

// ValidateMaterializedRouteManifestClosure proves the non-physical half of a
// canonical route receipt. It is suitable for full fsck when the receipt's
// target path is intentionally represented only by a digest and therefore
// cannot be reopened safely: manifest bytes must match the receipt, every
// payload entry must be identical in exact, and the configured claim set must
// partition every exact entry without gaps or overlaps.
//
// Physical bytes, hardlinks, permissions, and Nginx hostability remain the
// responsibility of ValidateMaterializedRouteRoot at target-bound admission.
func ValidateMaterializedRouteManifestClosure(route MaterializedRoute, exact, payload io.ReadSeeker) error {
	if err := route.Validate(); err != nil {
		return err
	}
	if exact == nil || payload == nil {
		return errors.New("materialized route manifest closure inputs are unavailable")
	}
	if err := verifyMaterializedRouteSeekable(exact, route.ExactManifestSHA256); err != nil {
		return fmt.Errorf("verify exact materialized route manifest: %w", err)
	}
	if err := verifyMaterializedRouteSeekable(payload, route.PayloadManifestSHA256); err != nil {
		return fmt.Errorf("verify payload materialized route manifest: %w", err)
	}
	if err := validateRoutePayloadSubset(exact, payload); err != nil {
		return err
	}
	if _, err := exact.Seek(0, io.SeekStart); err != nil {
		return err
	}
	claimEntries := make([]int, len(route.Claims))
	reader := manifest.NewReader(exact)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		matched := -1
		for index, claim := range route.Claims {
			if !materializedRouteClaimOwnsPath(claim, entry.Path) {
				continue
			}
			if matched != -1 {
				return fmt.Errorf("materialized route claims overlap at %s", entry.Path)
			}
			matched = index
		}
		if matched == -1 {
			return fmt.Errorf("exact materialized route entry %s is not covered by any claim", entry.Path)
		}
		claimEntries[matched]++
	}
	for index, count := range claimEntries {
		if count == 0 && route.Claims[index].Kind == MaterializedRouteClaimExactFile {
			return fmt.Errorf("materialized route claim at index %d owns no exact entry", index)
		}
	}
	_, exactErr := exact.Seek(0, io.SeekStart)
	_, payloadErr := payload.Seek(0, io.SeekStart)
	return errors.Join(exactErr, payloadErr)
}

func verifyMaterializedRouteSeekable(source io.ReadSeeker, want string) error {
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := VerifyMaterializedRouteManifest(source, want); err != nil {
		return err
	}
	_, err := source.Seek(0, io.SeekStart)
	return err
}

func materializedRouteClaimOwnsPath(claim MaterializedRouteClaim, candidate string) bool {
	switch claim.Kind {
	case MaterializedRouteClaimPrefix:
		return strings.HasPrefix(candidate, claim.RelativeRoot+"/")
	case MaterializedRouteClaimExactFile:
		return candidate == claim.RelativeRoot
	case MaterializedRouteClaimGeneration:
		prefix := claim.RelativeRoot + "/"
		if !strings.HasPrefix(candidate, prefix) {
			return false
		}
		parts := strings.Split(strings.TrimPrefix(candidate, prefix), "/")
		if len(parts) < 3 || !isMaterializedRouteGenerationID(parts[0]) {
			return false
		}
		leaf := strings.Split(claim.Leaf, "/")
		if len(parts) <= len(leaf)+1 {
			return false
		}
		for index := range leaf {
			if parts[index+1] != leaf[index] {
				return false
			}
		}
		relative := parts[len(leaf)+1:]
		return len(relative) == 3 && relative[0] == "Packages" && isNginxGenerationBucket(relative[1]) && isNginxGenerationRPM(relative[2]) ||
			len(relative) == 2 && relative[0] == "repodata" && isNginxGenerationMetadata(relative[1])
	default:
		return false
	}
}

func isNginxGenerationBucket(value string) bool {
	return len(value) == 1 && (value[0] >= 'a' && value[0] <= 'z' || value[0] >= '0' && value[0] <= '9' || value[0] == '_')
}

func isNginxGenerationRPM(value string) bool {
	if len(value) <= len(".rpm") || !strings.HasSuffix(value, ".rpm") || !isASCIIAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value)-len(".rpm"); index++ {
		if !isASCIIAlphaNumeric(value[index]) && !strings.ContainsRune("._+~^-", rune(value[index])) {
			return false
		}
	}
	return true
}

func isNginxGenerationMetadata(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for index := range len(value) {
		if !isASCIIAlphaNumeric(value[index]) && !strings.ContainsRune("._+~^@-", rune(value[index])) {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}
