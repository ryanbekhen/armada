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
	ReplicaPending = "pending"
	ReplicaPulling = "pulling"
	// ReplicaPulled: a held replica's images are on its node (ADR 0023).
	ReplicaPulled   = "pulled"
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
	// Restricted nodes only run apps whose placement selects one of their
	// labels.
	Restricted bool
	// Jobs is true when the node's agent runs job replicas (ADR 0019).
	Jobs bool
	// Volumes is true when the node mounts volumes (ADR 0023).
	Volumes bool
	// Containers is true when the node's agent runs init containers and
	// sidecars (ADR 0038).
	Containers bool
	// Subnet is the node's container subnet in the cluster network
	// (ADR 0025), given when the node is created; empty in clusters
	// without one.
	Subnet string
	// NetworkKey is the node's WireGuard public key, base64, as its agent
	// announced it (ADR 0025); empty until then.
	NetworkKey string
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
	// LastScheduled is the latest time a job's schedule fired; zero for
	// apps and jobs whose schedule has not fired yet.
	LastScheduled time.Time
	// Traffic splits requests between revisions in multiple revision mode,
	// with "latest" resolved (ADR 0022); it also lists the revisions still
	// serving while such an app rolls out to single mode.
	Traffic []spec.TrafficTarget
	// Removing is true from `armada app delete` until the app's replicas have
	// drained and the leader removes it.
	Removing bool
	// ScaledAt is when the autoscaler last changed the replica count; zero
	// until it does.
	ScaledAt time.Time
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

// RestartNote starts the messages an agent reports for a container it
// recreated, followed by why, until the container is ready.
const RestartNote = "restarted: "

// Replica is one scheduled instance of a revision on a node.
type Replica struct {
	ID          string
	App         string
	Revision    string
	NodeID      string
	State       string
	ContainerID string
	Address     string
	// IP is the container's address in its node's subnet of the cluster
	// network (ADR 0025), which every node's firewall keys on; empty
	// elsewhere.
	IP      string
	Message string
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
	// CreatedAt is when the replica was scheduled; zero for replicas
	// recorded before it was kept.
	CreatedAt time.Time
	// Restarts counts how often the agent recreated the replica's container
	// (it crashed, ran out of memory, or failed a probe). LastRestartAt is
	// when it last did, LastRestart why, as the agent reported it.
	Restarts      int
	LastRestartAt time.Time
	LastRestart   string
	// Run is the job run this replica is an attempt of (ADR 0019), 0 for
	// app replicas. Done marks an attempt that is over: its container is
	// stopped and kept for its logs. Finished and ExitCode are what the
	// agent reported when the container exited.
	Run      int64
	Done     bool
	Finished bool
	ExitCode int
	// Held marks a volume app's next replica during a rollout (ADR 0023):
	// its node pulls the images but starts nothing until the hold is
	// lifted, once the old replica is gone.
	Held bool
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
	IP          string
	Message     string
	Ready       bool
	// For job attempts: the container exited with ExitCode.
	Finished bool
	ExitCode int
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
	// Jobs, Volumes, and Containers as the agent reports them.
	Jobs       bool
	Volumes    bool
	Containers bool
	Egress     bool
	// NetworkKey as the agent announces it; empty keeps the recorded one.
	// A key another node holds is refused with ErrConflict.
	NetworkKey string
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

	// GetNetwork returns the cluster network (ADR 0025), or ErrNotFound
	// when the cluster has none.
	GetNetwork(ctx context.Context) (Network, error)
	// InitNetwork records the cluster network before the first node is
	// created; nodes created afterwards get a subnet from it.
	InitNetwork(ctx context.Context, n Network) error
	// SetDefaultIsolation turns network isolation of the default project on
	// or off; ErrPrecondition without a cluster network.
	SetDefaultIsolation(ctx context.Context, on bool, actor string) error

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

	// CreateProject records a new project (ADR 0026); ErrConflict if it
	// exists or is the default project. A non-nil by (a principal with
	// project-creator, else ErrPrecondition) becomes the project's admin in
	// the same transaction (ADR 0033).
	CreateProject(ctx context.Context, name, actor string, by *Principal) (Project, error)
	// GetProject returns a project; the default one always exists.
	GetProject(ctx context.Context, name string) (Project, error)
	// ListProjects lists every project, the default one first.
	ListProjects(ctx context.Context) ([]Project, error)
	// DeleteProject removes a project; ErrPrecondition while it still
	// holds apps, secrets, volumes, runs, or replicas, and for the default
	// project. Every role in it is taken back.
	DeleteProject(ctx context.Context, name, actor string) error

	// Access control (ADR 0033). CreateUser records a user (ErrConflict
	// while one of the name is on record) whose certificates issued before
	// p.Since are refused; KnowUser records a name not on record with
	// cluster-admin; SetUserSince refuses a user's older certificates.
	CreateUser(ctx context.Context, p Principal, actor string) (Principal, error)
	KnowUser(ctx context.Context, name string) error
	SetUserSince(ctx context.Context, name string, since time.Time, actor string) error
	// CreateService records a service (ErrConflict if it exists).
	CreateService(ctx context.Context, p Principal, actor string) (Principal, error)
	GetPrincipal(ctx context.Context, kind, name string) (Principal, error)
	// ListPrincipals lists users then services; kind "" lists both.
	ListPrincipals(ctx context.Context, kind string) ([]Principal, error)
	SetPrincipalLabels(ctx context.Context, kind, name string, labels map[string][]string, actor string) (Principal, error)
	// Assign and Unassign give and take back a role; projects must exist.
	Assign(ctx context.Context, kind, name string, g Grant, actor string) (Principal, error)
	Unassign(ctx context.Context, kind, name string, g Grant, actor string) (Principal, error)
	// DeletePrincipal deletes a service, or marks a user deleted so that
	// every certificate of the name is refused.
	DeletePrincipal(ctx context.Context, kind, name, actor string) error
	// RecordServiceCert records a certificate issued to a service; a
	// non-empty keep revokes every other one (renewal).
	RecordServiceCert(ctx context.Context, name string, c NodeCert, keep, actor string) error
	// UserAccess and ServiceAccess return a principal's roles and whether
	// its certificate is accepted; a user not on record has cluster-admin.
	UserAccess(ctx context.Context, name string, notBefore time.Time) (Principal, bool, error)
	ServiceAccess(ctx context.Context, name, serial string) (Principal, bool, error)

	// Deploy records spec as a new revision and makes it the rollout target
	// unless it is identical to the current target. A spec identical to the
	// active revision cancels a rollout in progress. The first revision of a
	// new app becomes active immediately. Deploy also resets the desired
	// replica count to spec.Replicas(), registers the spec's custom domains,
	// and returns ErrConflict if another app already routes one of its
	// host+path pairs. The app is stored under spec.ID(); ErrPrecondition
	// if its project does not exist.
	Deploy(ctx context.Context, s *spec.App, actor string) (rev Revision, created bool, err error)
	// DeployWith is Deploy with the checks of opts (ADR 0032), made in the
	// same transaction.
	DeployWith(ctx context.Context, s *spec.App, actor string, opts DeployOptions) (rev Revision, created bool, err error)
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
	// GetApps returns the apps that exist among names, by name, in far
	// fewer round trips than one GetApp each.
	GetApps(ctx context.Context, names []string) (map[string]App, error)
	// ListAppIDs returns the ID of every app and job, ordered, without
	// reading their records or revisions.
	ListAppIDs(ctx context.Context) ([]string, error)
	SetReplicas(ctx context.Context, app string, n int, actor string) error
	// SetTraffic changes the weights of an app in multiple revision mode.
	SetTraffic(ctx context.Context, app string, weights []spec.TrafficTarget, actor string) ([]spec.TrafficTarget, error)
	// AutoscaleReplicas sets an autoscaled app's count from from to n.
	AutoscaleReplicas(ctx context.Context, app string, from, n int, actor string) error

	GetRevision(ctx context.Context, name string) (Revision, error)
	// GetRevisions returns the revisions that exist among names, by name, in
	// far fewer round trips than one GetRevision each.
	GetRevisions(ctx context.Context, names []string) (map[string]Revision, error)
	ListRevisions(ctx context.Context, app string) ([]Revision, error)
	// SetRevisionDigest records the pinned image reference if none is set yet.
	SetRevisionDigest(ctx context.Context, revision, digest string) error
	// SetRevisionPlatforms records the image's platforms if none are set yet.
	SetRevisionPlatforms(ctx context.Context, revision string, platforms []string) error

	// CreateReplica schedules a replica. Its ID starts with "<app>-"
	// (ErrPrecondition otherwise), so one app's replicas are read by prefix.
	CreateReplica(ctx context.Context, r Replica) error
	DeleteReplica(ctx context.Context, id string) error
	// DrainReplica marks a replica as draining (idempotent).
	DrainReplica(ctx context.Context, id string) error
	// SetReplicaMoving marks a replica as being moved to another node, or
	// clears the mark.
	SetReplicaMoving(ctx context.Context, id string, moving bool) error
	// ReleaseReplica lifts a replica's hold (idempotent).
	ReleaseReplica(ctx context.Context, id string) error
	ListReplicas(ctx context.Context, f ReplicaFilter) ([]Replica, error)
	// UpdateReplicaStatus applies a status report from nodeID. It returns
	// ErrNotFound if the replica does not exist on that node, so one agent
	// cannot modify another node's replicas.
	UpdateReplicaStatus(ctx context.Context, nodeID string, st ReplicaStatus) error

	// Volumes (ADR 0023). CreateReplica binds the volumes its revision
	// mounts to its node, and refuses a node other than the one a volume
	// is bound to.
	ListVolumes(ctx context.Context, app string) ([]Volume, error)
	GetVolume(ctx context.Context, app, name string) (Volume, error)
	DeleteVolume(ctx context.Context, app, name, actor string) error
	BindVolume(ctx context.Context, app, name, node, actor string) error
	// RecordVolumeBackup keeps how a volume's backup went (ADR 0041).
	RecordVolumeBackup(ctx context.Context, app, name, id string, stored int64, snapshots int, errMsg string) error
	// PutEvent stores an event (ADR 0018) that expires after EventTTL and
	// deletes the event stored under replace, if set; it returns the new
	// key. ListEvents returns events that last happened at or after since,
	// oldest first; TrimEvents keeps only the newest keep.
	PutEvent(ctx context.Context, e Event, replace string) (string, error)
	ListEvents(ctx context.Context, since time.Time) ([]Event, error)
	TrimEvents(ctx context.Context, keep int) error

	// Jobs (ADR 0019); see the methods of Etcd in jobs.go.
	CreateJobRun(ctx context.Context, job, trigger string, at time.Time, actor string) (JobRun, error)
	SkipJobSchedule(ctx context.Context, job string, at time.Time) error
	UpdateJobRun(ctx context.Context, r JobRun) error
	ListJobRuns(ctx context.Context, job string) ([]JobRun, error)
	DeleteJobRun(ctx context.Context, job string, seq int64) error
	CancelJobRuns(ctx context.Context, job, actor string) ([]JobRun, error)
	DeleteJob(ctx context.Context, job, actor string) error
	// MarkAppRemoving starts removing an app: the reconciler drains its
	// replicas and then calls DeleteApp. Marking it again changes nothing.
	MarkAppRemoving(ctx context.Context, app, actor string) error
	// DeleteApp removes an app marked for removal with its revisions and
	// secrets, once it has no replicas. Its volumes stay.
	DeleteApp(ctx context.Context, app string) error
	SetReplicaDone(ctx context.Context, id string) error

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

// DeployOptions are the checks of a deploy that a person or tool asked for
// (ADR 0032).
type DeployOptions struct {
	// MustCreate refuses an app that exists (ErrConflict); MustExist one
	// that does not (ErrNotFound).
	MustCreate, MustExist bool
	// BaseRevision, when set, refuses the deploy (ErrPrecondition) unless
	// it is still the app's target revision: the change it was made from
	// is the latest.
	BaseRevision string
}
