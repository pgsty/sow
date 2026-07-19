package cli

import (
	"errors"
	"fmt"
	"path"

	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
)

// publicationChannelOwnerRepo resolves the independently published channel
// coordinate to its physical repository owner. Ordinary channels use the repo
// ID directly. A schema-v1 cross-EL compatibility channel uses the projection
// ID in its URL/checkpoint while inheriting target affinity and trust from the
// pinned source repo. Unknown/removed projection IDs never fall back to a repo
// prefix or selector heuristic.
func publicationChannelOwnerRepo(cfg *config.Config, channel pub.ChannelState) (config.Repo, error) {
	if cfg == nil {
		return config.Repo{}, errors.New("publication channel owner config is unavailable")
	}
	if repo, exists := cfg.RepoByName(channel.Repo); exists {
		if repo.Type != "yum" || repo.YUM == nil {
			return config.Repo{}, fmt.Errorf("channel %s names non-YUM repository %s", channel.RemoteKey, channel.Repo)
		}
		if channel.OS == "cross-el" {
			return config.Repo{}, fmt.Errorf("ordinary YUM channel %s cannot claim the cross-el coordinate", channel.RemoteKey)
		}
		expected := path.Join(".sow/channels", channel.View, channel.Repo, channel.OS, channel.Arch+".json")
		if channel.RemoteKey != expected {
			return config.Repo{}, fmt.Errorf("channel %s identity disagrees with coordinate %s", channel.RemoteKey, expected)
		}
		return repo, nil
	}
	projection, exists, err := config.YUMCompatibilityProjectionByID(cfg.CompatibilityProjections, channel.Repo)
	if err != nil {
		return config.Repo{}, err
	}
	if !exists {
		return config.Repo{}, fmt.Errorf("channel %s names unknown repository or YUM compatibility projection %s", channel.RemoteKey, channel.Repo)
	}
	if channel.View != projection.Source.View || channel.OS != "cross-el" || channel.Arch != projection.Source.Arch ||
		channel.LegacyRoot != projection.Root || channel.RemoteKey != expectedYUMCompatibilityChannelKey(channel.View, projection) {
		return config.Repo{}, fmt.Errorf("YUM compatibility channel %s disagrees with frozen projection %s", channel.RemoteKey, projection.ID)
	}
	owner, exists := cfg.RepoByName(projection.Source.Repo)
	if !exists || owner.Type != "yum" || owner.YUM == nil {
		return config.Repo{}, fmt.Errorf("YUM compatibility channel %s source owner %s is unavailable", channel.RemoteKey, projection.Source.Repo)
	}
	return owner, nil
}

func validatePublicationChannelOwners(cfg *config.Config, target string, generation pub.TargetGeneration) error {
	for _, channel := range generation.Channels {
		owner, err := publicationChannelOwnerRepo(cfg, channel)
		if err != nil {
			return fmt.Errorf("%w: %v", pub.ErrDrift, err)
		}
		if !owner.PublishesToTarget(target) {
			return fmt.Errorf("%w: target %s still contains channel %s after owner repo %s target affinity changed; perform an explicit full target reconciliation", pub.ErrDrift, target, channel.RemoteKey, owner.ID)
		}
	}
	return nil
}
