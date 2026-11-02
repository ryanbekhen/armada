// Package store persists cluster state. The Store interface is
// implemented by Etcd, which keeps the state in (embedded) etcd.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
)

// ErrNotFound is returned when a record does not exist (or, for scoped
// updates, does not belong to the caller).
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a change collides with another app, e.g. two
// apps routing the same host and path.
var ErrConflict = errors.New("conflict")

// ErrPrecondition means the operation needs some other state first, e.g. a
// deploy that references a secret that was never set, or deleting a secret
// that a serving revision still uses.
var ErrPrecondition = errors.New("failed precondition")

// ErrNotLeader is returned by a store fenced to a leadership term (see
// Etcd.Fenced) once that term is over: another control plane node leads.
var ErrNotLeader = errors.New("this server is no longer the leader")

// RevisionsToKeep is how many revisions per app are retained for rollback.
const RevisionsToKeep = 10

// Node states.
const (
	NodeReady   = "ready"
	NodeUnknown = "unknown"
)

// Replica states reported by agents.
const (
	ReplicaPending  = "pending"
	ReplicaPulling  = "pulling"
	ReplicaStarting = "starting"
	ReplicaRunning  = "running"
	ReplicaExited   = "exited"
	ReplicaFailed   = "failed"
)

// Node is a machine running an agent.
type Node struct {
	ID          string
	PrivateIP   string
	CPUMillis   int64
	MemoryBytes int64
	State       string
	LastSeen    time.Time
	CreatedAt   time.Time
	// Cordoned nodes receive no new replicas and are evacuated.
	Cordoned bool
	// Version is the Armada version its agent last reported.
	Version string
	// CertNotAfter is when the node's newest certificate expires (zero if
	// none is recorded).
	CertNotAfter time.Time
	// Labels are the admin labels (ADR 0014); OS and Arch are what its
	// agent reports. AllLabels combines them.
	Labels   map[string]string
	OS, Arch string
	// Runtime is the container runtime its agent reports (ADR 0015).
	Runtime string
	// Restricted nodes only run apps whose placement selects one of their
	// labels.
	Restricted bool
}

// AllLabels returns the admin labels plus armada.os and armada.arch.
func (n Node) AllLabels() map[string]string {
	out := make(map[string]string, len(n.Labels)+3)
	for k, v := range n.Labels {
		out[k] = v
	}
	if n.OS != "" {
		out[spec.LabelOS] = n.OS
	}
	if n.Arch != "" {
		out[spec.LabelArch] = n.Arch
	}
	if n.Runtime != "" {
		out[spec.LabelRuntime] = n.Runtime
	}
	return out
}

// JoinToken is a stored join token. The secret itself is never stored.
type JoinToken struct {
	ID         string
	SecretHash string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	CreatedBy  string
	// Server tokens add a control plane node and are redeemed only by
	// RedeemServerToken; node tokens only by RedeemJoinToken.
	Server bool
	// Labels are given to the node that joins with the token.
	Labels map[string]string
}

// Server is a control plane node.
type Server struct {
	Name      string
	PrivateIP string
	// APIAddr and JoinAddr are the private ip:port of its API and join
	// listeners (JoinAddr is empty if joining is disabled).
	APIAddr  string
	JoinAddr string
	// MemberID is its etcd member ID.
	MemberID uint64
	// Schema is the newest state schema its binary understands (1 for
	// records written before it was recorded), Version its Armada version.
	Schema    int
	Version   string
	CreatedAt time.Time
}

// NodeCert records an issued node certificate.
type NodeCert struct {
	Serial   string
	NotAfter time.Time
}

// Rollout states.
const (
	RolloutNone        = ""
	RolloutProgressing = "progressing"
	RolloutFailed      = "failed"
)

// App is a deployed application. ActiveRevision serves traffic;
// TargetRevision is what the app is rolling out to and equals
// ActiveRevision when no rollout is in progress.
type App struct {
	Name           string
	ActiveRevision string
	TargetRevision string
	Replicas       int
	Spec           *spec.App // spec of the active revision
	// RolloutState is RolloutProgressing while TargetRevision is being
	// rolled out, RolloutFailed after the last rollout was aborted, and
	// RolloutNone otherwise.
	RolloutState   string
	RolloutMessage string
	// RolloutProgressAt is when the rollout started or last made progress;
	// the progress deadline is measured from it.
	RolloutProgressAt time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Rolling reports whether a rollout is in progress.
func (a App) Rolling() bool {
	return a.RolloutState == RolloutProgressing && a.TargetRevision != a.ActiveRevision
}

// Revision is an immutable snapshot of an app spec.
type Revision struct {
	Name        string
	App         string
	Seq         int
	Spec        *spec.App
	ImageDigest string // pinned reference once an agent has pulled the image
	// Platforms lists the image's platforms ("os/arch") once an agent has
	// reported them; nil until then (ADR 0014).
	Platforms []string
	// Secrets pins the version of every secret the spec references.
	Secrets   map[string]int
	CreatedAt time.Time
}

// Image returns the digest-pinned reference if known, otherwise the spec image.
func (r Revision) Image() string {
	if r.ImageDigest != "" {
		return r.ImageDigest
	}
	return r.Spec.Image
}

// Replica is one scheduled instance of a revision on a node.
type Replica struct {
	ID          string
	App         string
	Revision    string
	NodeID      string
	State       string
	ContainerID string
	Address     string
	Message     string
	// Ready is the agent's latest readiness verdict; ReadySince is when it
	// last became ready (zero if not ready).
	Ready      bool
	ReadySince time.Time
	// DrainingSince is when the replica was taken out of the proxy before
	// removal; zero while it is in service.
	DrainingSince time.Time
	// MovingSince is when the scheduler decided to move the replica to
	// another node to spread its app (it keeps serving until a replacement
	// does); zero otherwise.
	MovingSince time.Time
	UpdatedAt   time.Time
}

// Moving reports whether the replica is being replaced on another node.
func (r Replica) Moving() bool { return !r.MovingSince.IsZero() }

// Draining reports whether the replica is on its way out.
func (r Replica) Draining() bool { return !r.DrainingSince.IsZero() }

// ReplicaFilter restricts ListReplicas. Empty fields match everything.
type ReplicaFilter struct {
	App    string
	NodeID string
}

// ReplicaStatus is the actual state of a replica as reported by its agent.
type ReplicaStatus struct {
	ID          string
	State       string
	ContainerID string
	Address     string
	Message     string
	Ready       bool
}

// NodeStatus is the runtime information an agent reports about its node.
type NodeStatus struct {
	State       string
	LastSeen    time.Time
	CPUMillis   int64
	MemoryBytes int64
	// Version is the agent's Armada version; empty keeps the recorded one.
	Version string
	// OS and Arch as the agent reports them; empty keeps the recorded ones.
	OS, Arch string
	// Runtime as the agent reports it; empty keeps the recorded one.
	Runtime string
}

// Domain is a custom domain referenced by at least one app. Apps may only
// receive traffic for it after ownership is proven with a DNS TXT record.
type Domain struct {
	Name       string
	Token      string
	Verified   bool
	VerifiedAt time.Time
	Message    string
	CreatedAt  time.Time
}

// SecretInfo describes the latest version of a secret. It never holds the
// value.
type SecretInfo struct {
	App       string
	Name      string
	Version   int
	UpdatedAt time.Time
	UpdatedBy string
	// UsedBy lists the app's revisions that pin some version of the secret.
	UsedBy []string
}

// AuditEvent records a change to desired state.
type AuditEvent struct {
	ID     int64
	At     time.Time
	Actor  string
	Action string
	Target string
	Detail string
}

// Store is the cluster state repository.
type Store interface {
	Close() error

	GetMeta(ctx context.Context, key string) (string, error)
	SetMeta(ctx context.Context, key, value string) error

	UpsertNode(ctx context.Context, n Node) error
	GetNode(ctx context.Context, id string) (Node, error)
	ListNodes(ctx context.Context) ([]Node, error)
	SetNodeStatus(ctx context.Context, id string, st NodeStatus) error
	// SetNodeCordoned marks a node (un)schedulable.
	SetNodeCordoned(ctx context.Context, id string, cordoned bool, actor string) error
	// SetNodeLabels sets and removes admin labels and returns the result.
	// Keys must already be validated; more than spec.MaxNodeLabels labels
	// is ErrPrecondition.
	SetNodeLabels(ctx context.Context, id string, set map[string]string, remove []string, actor string) (map[string]string, error)
	// SetNodeRestricted makes a node restricted or open (ADR 0014).
	SetNodeRestricted(ctx context.Context, id string, restricted bool, actor string) error
	// RemoveNode deletes a node and revokes its certificates. Unless force
	// is set it returns ErrPrecondition while replicas are scheduled on it;
	// with force they are deleted (and rescheduled elsewhere).
	RemoveNode(ctx context.Context, id string, force bool, actor string) error

	// CreateJoinToken stores a join token.
	CreateJoinToken(ctx context.Context, t JoinToken) error
	// RedeemJoinToken consumes token id for node n in one transaction: the
	// token must exist, be unused and unexpired, and its secret must pass
	// check; the node must not exist. issue is then called for the node's
	// certificate, which is recorded with the node. Every failure of the
	// token itself is reported as ErrNotFound so callers cannot tell why.
	RedeemJoinToken(ctx context.Context, id string, check func(secretHash string) bool, n Node, issue func() (NodeCert, error)) error
	// RedeemServerToken is RedeemJoinToken for a server token: it also
	// records srv, whose name must be new.
	RedeemServerToken(ctx context.Context, id string, check func(secretHash string) bool, srv Server, n Node, issue func() (NodeCert, error)) error
	// RecordNodeCert records a certificate issued to an existing node and
	// prunes expired ones. A non-empty keep (the serial of the certificate
	// that requested a renewal) revokes all other certificates of the node.
	RecordNodeCert(ctx context.Context, node string, c NodeCert, keep string) error
	// NodeCertAllowed reports whether serial is a valid certificate of an
	// existing node.
	NodeCertAllowed(ctx context.Context, node, serial string) (bool, error)

	// StoredSchema returns the schema the state is written in.
	StoredSchema(ctx context.Context) (int, error)
	// UpsertServer records a control plane node.
	UpsertServer(ctx context.Context, srv Server) error
	// ListServers lists the control plane nodes, sorted by name.
	ListServers(ctx context.Context) ([]Server, error)
	// RemoveServer deletes a control plane node's record.
	RemoveServer(ctx context.Context, name, actor string) error

	// Deploy records spec as a new revision and makes it the rollout target
	// unless it is identical to the current target. A spec identical to the
	// active revision cancels a rollout in progress. The first revision of a
	// new app becomes active immediately. Deploy also resets the desired
	// replica count to spec.Replicas(), registers the spec's custom domains,
	// and returns ErrConflict if another app already routes one of its
	// host+path pairs.
	Deploy(ctx context.Context, s *spec.App, actor string) (rev Revision, created bool, err error)
	// Rollback makes an existing revision of app the rollout target (or
	// cancels the rollout if it is the active revision).
	Rollback(ctx context.Context, app, revision, actor string) (Revision, error)
	// CompleteRollout makes revision active if it is still the target.
	CompleteRollout(ctx context.Context, app, revision string) error
	// FailRollout aborts the rollout to revision, if it is still the target,
	// and keeps the active revision.
	FailRollout(ctx context.Context, app, revision, message string) error
	// MarkRolloutProgress restarts the progress deadline of a rollout.
	MarkRolloutProgress(ctx context.Context, app string) error
	GetApp(ctx context.Context, name string) (App, error)
	ListApps(ctx context.Context) ([]App, error)
	SetReplicas(ctx context.Context, app string, n int, actor string) error

	GetRevision(ctx context.Context, name string) (Revision, error)
	ListRevisions(ctx context.Context, app string) ([]Revision, error)
	// SetRevisionDigest records the pinned image reference if none is set yet.
	SetRevisionDigest(ctx context.Context, revision, digest string) error
	// SetRevisionPlatforms records the image's platforms if none are set yet.
	SetRevisionPlatforms(ctx context.Context, revision string, platforms []string) error

	CreateReplica(ctx context.Context, r Replica) error
	DeleteReplica(ctx context.Context, id string) error
	// DrainReplica marks a replica as draining (idempotent).
	DrainReplica(ctx context.Context, id string) error
	// SetReplicaMoving marks a replica as being moved to another node, or
	// clears the mark.
	SetReplicaMoving(ctx context.Context, id string, moving bool) error
	ListReplicas(ctx context.Context, f ReplicaFilter) ([]Replica, error)
	// UpdateReplicaStatus applies a status report from nodeID. It returns
	// ErrNotFound if the replica does not exist on that node, so one agent
	// cannot modify another node's replicas.
	UpdateReplicaStatus(ctx context.Context, nodeID string, st ReplicaStatus) error

	ListAudit(ctx context.Context, limit int) ([]AuditEvent, error)
	// RecordAudit logs a change that has no transaction of its own.
	RecordAudit(ctx context.Context, actor, action, target, detail string) error

	// SetSecret stores a new version of an app's secret. seal encrypts the
	// value for the version number the store allocates. If rollout is set
	// and the app's target revision references the secret, a new revision
	// pinning the new version becomes the rollout target; its name is
	// returned.
	SetSecret(ctx context.Context, app, name string, seal func(version int) (secrets.Sealed, error), rollout bool, actor string) (version int, revision string, err error)
	// GetSecret returns one encrypted secret version.
	GetSecret(ctx context.Context, app, name string, version int) (secrets.Sealed, error)
	// ListSecrets describes an app's secrets, sorted by name.
	ListSecrets(ctx context.Context, app string) ([]SecretInfo, error)
	// DeleteSecret removes every version of a secret. It returns
	// ErrPrecondition if the app's active or target revision uses it.
	DeleteSecret(ctx context.Context, app, name, actor string) error

	ListDomains(ctx context.Context) ([]Domain, error)
	GetDomain(ctx context.Context, name string) (Domain, error)
	SetDomainVerification(ctx context.Context, name string, verified bool, message string) error
}
