package managed

import (
	"errors"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

var (
	ErrWorkspaceInput = errors.New("managed: workspace discovery or configuration error")
	ErrRejected       = errors.New("managed: operation rejected")
	ErrIntegrity      = errors.New("managed: integrity or recovery failure")
	ErrNotReady       = errors.New("managed: repository is not ready to copy")
)

type WorkspaceOptions struct {
	Workdir string
	CWD     string
	SOWDir  string
}

type LockOptions struct {
	Timeout time.Duration
	NoWait  bool
}

type InitOptions struct {
	LockOptions
	Dir   string
	Fault func(string) error
}

type InitResult struct {
	Workspace               string   `json:"workspace"`
	ConfigCreated           bool     `json:"config_created"`
	RepositoriesInitialized int      `json:"repositories_initialized"`
	DistsInitialized        int      `json:"dists_initialized"`
	Existing                []string `json:"existing"`
}

func (r InitResult) HasCommittedChanges() bool {
	return r.ConfigCreated || r.RepositoriesInitialized > 0 || r.DistsInitialized > 0
}

type ConfigCheckResult struct {
	Workspace    string `json:"workspace"`
	Repositories int    `json:"repositories"`
	Dists        int    `json:"dists"`
}

type ConfigShowOptions struct {
	WorkspaceOptions
	Repository string
	Dist       string
	Dists      []string
	All        bool
}

type RepositoryInfo struct {
	Name            string                     `json:"name"`
	Path            string                     `json:"path"`
	Protected       bool                       `json:"protected"`
	Dists           int64                      `json:"dists"`
	Generation      state.GenerationID         `json:"generation"`
	DesiredRevision int64                      `json:"desired_revision"`
	Status          string                     `json:"status"`
	Packages        int64                      `json:"packages"`
	Memberships     int64                      `json:"memberships"`
	DirtyReasons    []string                   `json:"dirty_reasons,omitempty"`
	RecentOperation *OperationInfo             `json:"recent_operation,omitempty"`
	Config          config.EffectiveRepository `json:"config"`
}

// OperationInfo is the public, secret-safe projection used by repo show. The
// recovery payload deliberately remains private because it can contain a full
// staged configuration document and is not part of the P1 CLI contract.
type OperationInfo struct {
	ID         string               `json:"id"`
	Kind       string               `json:"kind"`
	State      state.OperationState `json:"state"`
	ErrorClass string               `json:"error_class,omitempty"`
	CreatedAt  time.Time            `json:"created_at"`
	UpdatedAt  time.Time            `json:"updated_at"`
}

type RepositoryNewOptions struct {
	WorkspaceOptions
	LockOptions
	Name  string
	Fault func(string) error
}

type RepositoryShowOptions struct {
	WorkspaceOptions
	Repository string
	Name       string
}

type RepositoryRemoveOptions struct {
	WorkspaceOptions
	LockOptions
	Name  string
	Force bool
	Fault func(string) error
}

type RemovalResult struct {
	Removed bool `json:"removed"`
	Noop    bool `json:"noop"`
}

type DistInfo struct {
	Name               string               `json:"name"`
	Format             string               `json:"format"`
	Architectures      []state.Architecture `json:"architectures"`
	DesiredMembers     int64                `json:"desired_members"`
	BuiltMembers       int64                `json:"built_members"`
	Generation         state.GenerationID   `json:"generation"`
	Dirty              bool                 `json:"dirty"`
	Status             string               `json:"status"`
	EffectiveConfigSHA string               `json:"effective_config_sha256"`
	DirtyReasons       []string             `json:"dirty_reasons,omitempty"`
	Config             config.EffectiveDist `json:"config"`
}

type DistListOptions struct {
	WorkspaceOptions
	Repository string
}

type DistShowOptions struct {
	WorkspaceOptions
	Repository string
	Name       string
}

type DistNewOptions struct {
	WorkspaceOptions
	LockOptions
	Repository string
	Name       string
	Format     string
	Fault      func(string) error
}

type DistRemoveOptions struct {
	WorkspaceOptions
	LockOptions
	Repository string
	Name       string
	Force      bool
	Fault      func(string) error
}

type AddOptions struct {
	WorkspaceOptions
	LockOptions
	Repository string
	Dists      []string
	Paths      []string
	Recursive  bool
	Skip       bool
	Jobs       int
	Fault      func(string) error
}

type MutationItem struct {
	Input      string            `json:"input"`
	Status     string            `json:"status"`
	Format     string            `json:"format,omitempty"`
	Coordinate string            `json:"coordinate,omitempty"`
	SHA256     string            `json:"sha256,omitempty"`
	Dists      map[string]string `json:"dists,omitempty"`
	Error      string            `json:"error,omitempty"`
}

type AddResult struct {
	Operation         string             `json:"operation"`
	Repository        string             `json:"repository"`
	Revision          int64              `json:"desired_revision"`
	Generation        state.GenerationID `json:"built_generation"`
	Dirty             bool               `json:"dirty"`
	Accepted          int                `json:"accepted"`
	Failed            int                `json:"failed"`
	MembershipAdded   int                `json:"memberships_added"`
	MembershipRemoved int                `json:"memberships_removed"`
	Items             []MutationItem     `json:"items"`
}

type RemoveOptions struct {
	WorkspaceOptions
	LockOptions
	Repository string
	Dists      []string
	Packages   []string
	Check      bool
	Skip       bool
	Jobs       int
	Fault      func(string) error
}

type RemovedMembership struct {
	Dist       string `json:"dist"`
	SHA256     string `json:"sha256"`
	Coordinate string `json:"coordinate"`
	Name       string `json:"name"`
}

type RemoveResult struct {
	Operation  string              `json:"operation,omitempty"`
	Repository string              `json:"repository"`
	Revision   int64               `json:"desired_revision"`
	Generation state.GenerationID  `json:"built_generation"`
	Dirty      bool                `json:"dirty"`
	Check      bool                `json:"check"`
	Removed    []RemovedMembership `json:"removed"`
	Dists      []string            `json:"dists"`
	Changes    []state.FileChange  `json:"changes"`
}

type BuildOptions struct {
	WorkspaceOptions
	LockOptions
	Repository string
	Dists      []string
	Jobs       int
	Fault      func(string) error
}

type BuildResult struct {
	Operation  string             `json:"operation"`
	Repository string             `json:"repository"`
	Dists      []string           `json:"dists"`
	Revision   int64              `json:"desired_revision"`
	Generation state.GenerationID `json:"built_generation"`
	Noop       bool               `json:"noop"`
	Dirty      bool               `json:"dirty"`
}

type PackageListOptions struct {
	WorkspaceOptions
	Repository string
	Dists      []string
}

type PackageListResult struct {
	Repository string                `json:"repository"`
	Dists      []string              `json:"dists"`
	Dirty      bool                  `json:"dirty"`
	Packages   []state.PackageObject `json:"packages"`
}

type PackageShowOptions struct {
	WorkspaceOptions
	Repository string
	Dists      []string
	Reference  string
}

type PackageShowResult struct {
	Repository string              `json:"repository"`
	Package    state.PackageObject `json:"package"`
}

type PackageLocation struct {
	Repository string   `json:"repository"`
	Dists      []string `json:"dists"`
	BuiltDists []string `json:"built_dists"`
	SHA256     string   `json:"sha256"`
	Coordinate string   `json:"coordinate"`
}

type PackageWhereOptions struct {
	WorkspaceOptions
	Repository string
	Dists      []string
	Reference  string
}

type PackageWhereResult struct {
	Reference string            `json:"reference"`
	Locations []PackageLocation `json:"locations"`
}

type StatusOptions struct {
	WorkspaceOptions
	Repository string
	Dists      []string
}

type PendingPayloadInfo struct {
	Count int64 `json:"count"`
	Bytes int64 `json:"bytes"`
}

type StatusResult struct {
	Repository       string             `json:"repository"`
	Status           string             `json:"status"`
	ReadyToCopy      bool               `json:"ready_to_copy"`
	DesiredRevision  int64              `json:"desired_revision"`
	BuiltGeneration  state.GenerationID `json:"built_generation"`
	DirtyDists       []string           `json:"dirty_dists"`
	DirtyReasons     []string           `json:"dirty_reasons"`
	Pending          PendingPayloadInfo `json:"pending"`
	Operation        *OperationInfo     `json:"pending_operation,omitempty"`
	RecentOperation  *OperationInfo     `json:"recent_operation,omitempty"`
	RepositoryLocked bool               `json:"repository_locked"`
	LockHolder       string             `json:"lock_holder,omitempty"`
}

type ChangesOptions struct {
	WorkspaceOptions
	Repository string
	Base       *state.GenerationID
}

type ChangesResult struct {
	Repository string             `json:"repository"`
	Base       state.GenerationID `json:"base"`
	Generation state.GenerationID `json:"generation"`
	Dirty      bool               `json:"dirty"`
	Changes    []state.FileChange `json:"changes"`
}

type LogOptions struct {
	WorkspaceOptions
	Repository string
	Dists      []string
	Operation  string
}

type LogResult struct {
	Repository string                 `json:"repository"`
	Operations []state.Operation      `json:"operations,omitempty"`
	Detail     *state.OperationDetail `json:"detail,omitempty"`
}

type LogPruneOptions struct {
	WorkspaceOptions
	LockOptions
	Repository string
	Before     time.Time
	Fault      func(string) error
}

type LogPruneResult struct {
	Operation  string    `json:"operation"`
	Repository string    `json:"repository"`
	Before     time.Time `json:"before"`
	Pruned     int64     `json:"pruned"`
}

type CheckOptions struct {
	WorkspaceOptions
	Repository string
	Dists      []string
	Jobs       int
}

type CheckLayer struct {
	Name    string   `json:"name"`
	OK      bool     `json:"ok"`
	Checked int64    `json:"checked"`
	Issues  []string `json:"issues"`
}

type CheckResult struct {
	Repository  string             `json:"repository"`
	Status      string             `json:"status"`
	ReadyToCopy bool               `json:"ready_to_copy"`
	Generation  state.GenerationID `json:"built_generation"`
	Revision    int64              `json:"desired_revision"`
	Layers      []CheckLayer       `json:"layers"`
}

type PartialError struct {
	Result any
}

func (e *PartialError) Error() string { return "managed: batch partially succeeded" }
