package syncer

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type Candidate struct {
	Format    string
	Name      string
	Version   string
	Arch      string
	URL       string
	Size      int64
	SHA256    string
	DebugInfo bool
}

func (c Candidate) Validate() error {
	if c.Format != "rpm" && c.Format != "deb" {
		return fmt.Errorf("candidate format must be rpm or deb")
	}
	if c.Name == "" || c.Version == "" || c.Arch == "" || strings.ContainsAny(c.Name+c.Version+c.Arch, "\x00\t\r\n") {
		return fmt.Errorf("candidate name, version, and arch are required and must be safe")
	}
	parsed, err := url.Parse(c.URL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("candidate URL must be absolute HTTP(S) without credentials, query, or fragment")
	}
	if c.Size < 0 {
		return fmt.Errorf("candidate size cannot be negative")
	}
	decoded, err := hex.DecodeString(c.SHA256)
	if err != nil || len(decoded) != sha256.Size || strings.ToLower(c.SHA256) != c.SHA256 {
		return fmt.Errorf("candidate SHA256 must be lowercase hex")
	}
	return nil
}

type Inventory interface {
	Has(sha256 string, size int64) (bool, error)
}

type Plan struct {
	Download      []Candidate
	DownloadCount int
	Present       int
	Filtered      int
}

// CandidateStream yields candidates in ascending SHA-256 order. This ordering
// lets BuildPlanStream detect duplicates with O(1) state instead of retaining a
// repository-sized digest map.
type CandidateStream func(func(Candidate) error) error

// BuildPlanStream filters and diffs a disk-backed candidate stream. Handlers
// run synchronously for each selected candidate and should either consume it or
// copy only the deliberate change set they need to retain.
func BuildPlanStream(stream CandidateStream, filter Filter, inventory Inventory, present, download func(Candidate) error) (Plan, error) {
	if stream == nil || inventory == nil {
		return Plan{}, fmt.Errorf("candidate stream and inventory are required")
	}
	if err := filter.Validate(); err != nil {
		return Plan{}, err
	}
	var plan Plan
	var prior Candidate
	havePrior := false
	err := stream(func(candidate Candidate) error {
		if err := candidate.Validate(); err != nil {
			return fmt.Errorf("candidate %s: %w", candidate.Name, err)
		}
		if havePrior {
			if candidate.SHA256 < prior.SHA256 {
				return fmt.Errorf("candidate stream is not ordered by SHA256")
			}
			if candidate.SHA256 == prior.SHA256 {
				if candidate != prior {
					return fmt.Errorf("same SHA256 has conflicting identities for %s", candidate.Name)
				}
				return nil
			}
		}
		prior = candidate
		havePrior = true
		if !filter.Match(candidate.Name, candidate.Arch, candidate.DebugInfo) {
			plan.Filtered++
			return nil
		}
		has, err := inventory.Has(candidate.SHA256, candidate.Size)
		if err != nil {
			return err
		}
		if has {
			plan.Present++
			if present != nil {
				return present(candidate)
			}
			return nil
		}
		plan.DownloadCount++
		if download != nil {
			return download(candidate)
		}
		return nil
	})
	return plan, err
}

func BuildPlan(candidates []Candidate, filter Filter, inventory Inventory) (Plan, error) {
	if err := filter.Validate(); err != nil {
		return Plan{}, err
	}
	seen := make(map[string]Candidate)
	var plan Plan
	for _, candidate := range candidates {
		if err := candidate.Validate(); err != nil {
			return Plan{}, fmt.Errorf("candidate %s: %w", candidate.Name, err)
		}
		if !filter.Match(candidate.Name, candidate.Arch, candidate.DebugInfo) {
			plan.Filtered++
			continue
		}
		if prior, exists := seen[candidate.SHA256]; exists {
			if prior.Size != candidate.Size {
				return Plan{}, fmt.Errorf("same SHA256 has conflicting sizes for %s", candidate.Name)
			}
			continue
		}
		seen[candidate.SHA256] = candidate
		has, err := inventory.Has(candidate.SHA256, candidate.Size)
		if err != nil {
			return Plan{}, err
		}
		if has {
			plan.Present++
			continue
		}
		plan.Download = append(plan.Download, candidate)
	}
	sort.Slice(plan.Download, func(i, j int) bool {
		left, right := plan.Download[i], plan.Download[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Arch != right.Arch {
			return left.Arch < right.Arch
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		return left.SHA256 < right.SHA256
	})
	plan.DownloadCount = len(plan.Download)
	return plan, nil
}
