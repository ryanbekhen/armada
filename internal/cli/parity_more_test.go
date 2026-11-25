package cli

import (
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/clientconfig"
)

// The answers and cases of the commands of pull request 17b: volume,
// snapshot, domain, cluster, node, server, user, service, role, alert,
// metrics, and app logs, exec, top, and events.

var day = time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)

func at(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }

// pemCert stands for an issued certificate; the client only stores it.
const pemCert = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ\n-----END CERTIFICATE-----\n"

func issued() *armadav1.IssueMetricsCertificateResponse {
	return &armadav1.IssueMetricsCertificateResponse{Cert: []byte(pemCert), CaCert: []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"), ExpiresAt: at(day.AddDate(1, 0, 0))}
}

func nodes() []*armadav1.NodeStatus {
	return []*armadav1.NodeStatus{
		{Id: "node1", PrivateIp: "10.0.0.11", State: "ready", LastSeen: ts(12 * time.Second), CpuMillis: 2350, MemoryBytes: 3 << 30, Version: "v0.1.0-alpha.41",
			CertExpiresAt: at(day.AddDate(0, 0, 30)), Labels: map[string]string{"zone": "a", "disk": "ssd"}, Replicas: 4,
			Runtime: &armadav1.RuntimeStatus{Agent: "supervisor-rust", ImagesToPull: 2, Converting: true}},
		{Id: "node2", PrivateIp: "10.0.0.12", State: "ready", Cordoned: true, Restricted: true, Site: "office", Endpoint: "203.0.113.5", Relay: true, RelayPinned: true,
			Runtime: &armadav1.RuntimeStatus{Agent: "containerd", MoveError: "busy\x1b"}},
		{Id: "node3", PrivateIp: "10.122.0.3", State: "lost", BehindNat: true, RelayPinned: true, MemoryBytes: 512 << 20,
			Runtime: &armadav1.RuntimeStatus{Agent: "supervisor-go"}},
	}
}

func volumes() *armadav1.ListVolumesResponse {
	return &armadav1.ListVolumesResponse{Volumes: []*armadav1.Volume{
		{App: "db", Name: "data", Node: "node1", CreatedAt: ts(50 * time.Hour), InUse: true, UsedBytes: 5 << 30, Path: "/var/lib/db", Backup: true,
			LastBackupAt: ts(2 * time.Hour), BackupSnapshots: 12, BackupStoredBytes: 1500 << 20},
		{App: "db", Name: "logs", Node: "node1", CreatedAt: ts(3 * time.Minute), UsedBytes: -1, Backup: true, BackupFailedAt: ts(time.Minute)},
		{App: "cache.shop", Name: "tmp", Node: "node2", CreatedAt: ts(time.Hour), InUse: true, UsedBytes: 700, Path: "/tmp/x"},
	}}
}

func principals() *armadav1.ListPrincipalsResponse {
	return &armadav1.ListPrincipalsResponse{YouKind: "user", You: "ada", Principals: []*armadav1.Principal{
		{Kind: "user", Name: "ada", Roles: []*armadav1.RoleAssignment{{Role: "cluster-admin"}}, CreatedAt: at(day)},
		{Kind: "user", Name: "ana", Roles: []*armadav1.RoleAssignment{{Role: "deployer", Space: "shop"}, {Role: "viewer"}}, CreatedBy: "ada",
			Labels: []*armadav1.LabelAllowance{{Key: "team", Values: []string{"web", "api"}}}, CreatedAt: at(day)},
		{Kind: "user", Name: "old", Removed: true},
		{Kind: "service", Name: "ci", Roles: []*armadav1.RoleAssignment{{Role: "deployer", Space: "shop"}}, Certificates: 2, CertExpiresAt: at(day.AddDate(0, 3, 0)), CreatedAt: at(day)},
	}}
}

func roles() *armadav1.ListRolesResponse {
	return &armadav1.ListRolesResponse{Roles: []*armadav1.RoleInfo{
		{Name: "viewer", Description: "read everything in its scope", Cluster: true, Space: true, Methods: []string{"Status", "ListApps"}},
		{Name: "deployer", Description: "deploy apps", Space: true, Methods: []string{"Deploy"}},
		{Name: "cluster-admin", Description: "everything", Cluster: true},
	}}
}

func clusterConfig() *armadav1.ClusterConfig {
	return &armadav1.ClusterConfig{RootDomain: "apps.example.com", TrustedProxies: []string{"173.245.48.0/20"}, Tls: true, AcmeCa: "letsencrypt",
		AcmeEmail: "ops@example.com", DnsProvider: "cloudflare", DnsTokenSet: true, MetricsPort: 9100, NodeLostTimeoutSeconds: 120,
		LogRetentionSeconds: 336 * 3600, LogMaxBytes: 2 << 30, LogExport: "loki", LogEndpoint: "https://logs.example.com/loki/api/v1/push", LogExportUser: "u", LogExportTenant: "t",
		Network: "wireguard", NetworkSwitchTo: "plain", MeshCidr: "10.122.0.0/16", BackupBucket: "s3.example.com/b/p", BackupEverySeconds: 3600, BackupTimeZone: "Asia/Jakarta",
		BackupKeep: &armadav1.BackupKeep{Last: 3, Daily: 7}}
}

func clusterStatus() *armadav1.ClusterStatusResponse {
	return &armadav1.ClusterStatusResponse{Nodes: 3, NodesReady: 2, Apps: 25, AppsReady: 22, AppsProgressing: 1, AppsFailing: 2, Jobs: 4,
		Attention:      []*armadav1.AppSummary{{Name: "web", Ready: 1, Desired: 2, State: "progressing"}, {Name: "api.shop", State: "failed", Message: "crash\x07loop"}},
		AttentionTotal: 3, NodesNotReady: []string{"node3"},
		ControlPlaneBackup: &armadav1.ControlPlaneBackupStatus{Bucket: "s3.example.com/b", LastAt: at(day), LastServer: "s1", LastSizeBytes: 3 << 20, StoredBytes: 9 << 20, Snapshots: 4,
			NextAt: at(day.Add(time.Hour)), FailedAt: at(day.Add(time.Minute)), Error: "denied\x1b"},
		Runtime: &armadav1.RuntimeProgress{Nodes: 3, Moved: 1, OthersTotal: 4, Others: []*armadav1.NodeRuntime{{Node: "node2", Status: &armadav1.RuntimeStatus{Agent: "containerd"}},
			{Node: "node3"}, {Node: "node4", Status: &armadav1.RuntimeStatus{Agent: "supervisor-rust", ImagesToPull: 3}}}},
		RuntimeMove: &armadav1.RuntimeMoveStatus{Node: "node2", Step: "draining", SinceUnix: day.Unix(), StepSinceUnix: day.Add(time.Minute).Unix(), Error: "x",
			Waiting: []*armadav1.RuntimeMoveWait{{Node: "node5", Reason: "an older agent", Operator: true}}, WaitingTotal: 2},
		NetworkSwitch: &armadav1.NetworkSwitchProgress{From: "plain", To: "wireguard", Step: "prepare", SinceUnix: day.Unix(), WaitingTotal: 5, Waiting: []*armadav1.NodeSwitchWait{
			{Node: "a", Unsupported: true}, {Node: "b", Disconnected: true}, {Node: "c", Error: "e\x07"}, {Node: "d", Unreached: []string{"x", "y"}}}},
	}
}

func topAnswer() *armadav1.TopResponse {
	return &armadav1.TopResponse{
		Replicas: []*armadav1.ReplicaTop{
			{Id: "web-r2-k3p9x", App: "web", NodeId: "node1", State: "running", Measured: true, CpuMillis: 120, CpuReservedMillis: 250, MemoryBytes: 200 << 20, MemoryLimitBytes: 512 << 20},
			{Id: "web-r2-m2x8q", App: "web", State: "starting", CpuReservedMillis: 250, MemoryLimitBytes: 512 << 20},
			{Id: "api-r3-aaaaa", App: "api.shop", NodeId: "node2", Measured: true, CpuMillis: 0, MemoryBytes: 0, CpuReservedMillis: 100, MemoryLimitBytes: 2 << 30},
		},
		Nodes: []*armadav1.NodeTop{
			{Id: "node1", Measured: true, Replicas: 4, CpuMillis: 900, CpuReservedMillis: 1200, CpuAllocatableMillis: 3800, MemoryBytes: 3 << 30, MemoryReservedBytes: 4 << 30, MemoryAllocatableBytes: 15 << 30},
			{Id: "node2", Replicas: 0, CpuAllocatableMillis: 1900},
		},
		Spaces: []*armadav1.SpaceTop{
			{Name: "default", Replicas: 3, Measured: 2, CpuMillis: 300, CpuReservedMillis: 600, MemoryBytes: 1 << 30, MemoryReservedBytes: 2 << 30, VolumeBytes: 5 << 30, Requests: 1234, EgressBytes: 3 << 20},
			{Name: "shop", Replicas: 1},
		},
		CountedSince: at(day),
	}
}

func eventInfos() []proto.Message {
	return []proto.Message{
		&armadav1.EventInfo{Kind: "replica", Object: "web-r2-k3p9x", App: "web", Reason: "Crashed", Message: "exit 1\x1b[31m", Count: 3, Last: ts(time.Minute)},
		&armadav1.EventInfo{Kind: "node", Object: "node2", Node: "node2", Reason: "NodeLost", Count: 1, Last: at(day.AddDate(0, -1, 0))},
		&armadav1.EventInfo{Kind: "replica", Object: "api-r1-x", App: "api.shop", Reason: "Started", Count: 1, Last: ts(time.Minute)},
		&armadav1.EventInfo{Kind: "app", Object: "a-very-long-object-name-that-is-wider-than-the-column", App: "web", Reason: "RolloutComplete", Count: 12345, Message: "done", Last: ts(time.Minute)},
	}
}

func logEntries() []proto.Message {
	return []proto.Message{
		&armadav1.LogEntry{Replica: "web-r2-k3p9x", Stream: armadav1.Stream_STREAM_STDOUT, Data: []byte("GET / 200\n"), Time: at(day.Add(1500 * time.Millisecond))},
		&armadav1.LogEntry{Replica: "web-r2-m2x8q", Stream: armadav1.Stream_STREAM_STDERR, Data: []byte("warn: slow\n")},
		&armadav1.LogEntry{Stream: armadav1.Stream_STREAM_STDOUT, Data: []byte("no replica\n"), Time: at(day)},
	}
}

func execAnswer(code int32, msgs ...proto.Message) []answer {
	out := []proto.Message{&armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_Replica{Replica: "web-r2-k3p9x"}}}
	out = append(out, msgs...)
	out = append(out, &armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_ExitCode{ExitCode: code}})
	return []answer{{stream: out}}
}

func stdout(s string) proto.Message {
	return &armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_Stdout{Stdout: []byte(s)}}
}

func stderr(s string) proto.Message {
	return &armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_Stderr{Stderr: []byte(s)}}
}

// moreAnswers are the default answers of 17b's methods.
func moreAnswers() map[string][]answer {
	channels := &armadav1.ListAlertChannelsResponse{Channels: []*armadav1.AlertChannel{
		{Name: "ops", Type: "slack", Sent: 4, LastSent: ts(5 * time.Minute)},
		{Name: "oncall", Type: "telegram", ChatId: "-100123", Spaces: []string{"shop", "billing"}, Reasons: []string{"Crashed", "OutOfMemory"}, Failed: 2, LastError: "chat not found"},
		{Name: "mail", Type: "email", To: []string{"a@example.com", "b@example.com"}},
	}}
	return map[string][]answer{
		"ListVolumes":           okAnswer(volumes()),
		"RemoveVolume":          okAnswer(&armadav1.RemoveVolumeResponse{}),
		"ListVolumeSnapshots":   okAnswer(&armadav1.ListVolumeSnapshotsResponse{Snapshots: []*armadav1.VolumeSnapshot{{Id: "20261120T093000-ab12cd34", Time: at(day)}, {Id: "x", Time: ts(time.Hour)}}}),
		"CreateVolumeSnapshot":  okAnswer(&armadav1.CreateVolumeSnapshotResponse{Snapshot: &armadav1.VolumeSnapshot{Id: "s1", Files: 42, Bytes: 10 << 20}, NewBytes: 1 << 20, StoredBytes: 30 << 20, Snapshots: 5}),
		"RestoreVolumeSnapshot": okAnswer(&armadav1.RestoreVolumeResponse{Node: "node2"}),
		"RestoreVolume":         {{msg: &armadav1.RestoreVolumeResponse{Node: "node1"}}},
		"BackupVolume":          streamAnswer(codes.OK, "", &armadav1.VolumeData{Data: []byte("gz-part-1,")}, &armadav1.VolumeData{Data: []byte("part-2"), Done: true}),
		"ListDomains": okAnswer(&armadav1.ListDomainsResponse{Domains: []*armadav1.Domain{
			{Name: "www.example.com", Apps: []string{"web"}, Verified: true, TlsReady: true},
			{Name: "shop.example.com", Apps: []string{"api.shop"}, TxtName: "_armada.shop.example.com", TxtValue: "armada-verify=abc\"x", Message: "no TXT\x07"},
			{Name: "new.example.com", TxtName: "_armada.new.example.com", TxtValue: "v"},
		}}),
		"VerifyDomain":            okAnswer(&armadav1.Domain{Name: "www.example.com", Apps: []string{"web", "api"}, TxtName: "_armada.www.example.com", TxtValue: "v"}),
		"ClusterStatus":           okAnswer(clusterStatus()),
		"GetClusterConfig":        okAnswer(clusterConfig()),
		"SetClusterConfig":        okAnswer(clusterConfig()),
		"Top":                     okAnswer(topAnswer()),
		"Events":                  streamAnswer(codes.OK, "", eventInfos()...),
		"Logs":                    streamAnswer(codes.OK, "", logEntries()...),
		"Exec":                    execAnswer(0, stdout("hello\n"), stderr("oops\n")),
		"CordonNode":              okAnswer(&armadav1.CordonNodeResponse{}),
		"RemoveNode":              okAnswer(&armadav1.RemoveNodeResponse{}),
		"LabelNode":               okAnswer(&armadav1.LabelNodeResponse{Labels: map[string]string{"region": "sulawesi", "kind": "raspi"}}),
		"RestrictNode":            okAnswer(&armadav1.RestrictNodeResponse{}),
		"SetNodeSite":             okAnswer(&armadav1.SetNodeSiteResponse{}),
		"SetNodeRelay":            okAnswer(&armadav1.SetNodeRelayResponse{}),
		"RotateNodeKey":           okAnswer(&armadav1.RotateNodeKeyResponse{}),
		"CreateJoinToken":         okAnswer(&armadav1.CreateJoinTokenResponse{Token: "tok.en", CaHash: "sha256:abc", JoinAddr: "10.0.0.1:7444", ExpiresAt: at(day), Version: "v0.1.0-alpha.41"}),
		"RemoveServer":            okAnswer(&armadav1.RemoveServerResponse{}),
		"CreateUser":              okAnswer(issued()),
		"IssueUserCertificate":    okAnswer(issued()),
		"IssueServiceCertificate": okAnswer(issued()),
		"CreateService":           okAnswer(&armadav1.Principal{Kind: "service", Name: "ci", Roles: []*armadav1.RoleAssignment{{Role: "deployer", Space: "shop"}}}),
		"ListPrincipals":          okAnswer(principals()),
		"UpdatePrincipal":         okAnswer(&armadav1.Principal{Labels: []*armadav1.LabelAllowance{{Key: "team", Values: []string{"web"}}}}),
		"DeletePrincipal":         okAnswer(&armadav1.DeletePrincipalResponse{}),
		"CreateAssignment":        okAnswer(&armadav1.Principal{Roles: []*armadav1.RoleAssignment{{Role: "deployer", Space: "shop"}, {Role: "viewer"}}}),
		"DeleteAssignment":        okAnswer(&armadav1.Principal{}),
		"ListRoles":               okAnswer(roles()),
		"RenewOwnCertificate":     okAnswer(issued()),
		"IssueMetricsCertificate": okAnswer(issued()),
		"ListMetricsCredentials": okAnswer(&armadav1.ListMetricsCredentialsResponse{Credentials: []*armadav1.MetricsCredential{
			{Name: "prometheus", Certificates: []*armadav1.MetricsCertificate{{Serial: "1", ExpiresAt: at(day)}, {Serial: "2", ExpiresAt: at(day.AddDate(1, 0, 0))}}},
			{Name: "none"},
		}}),
		"RevokeMetricsCredentials": okAnswer(&armadav1.RevokeMetricsCredentialsResponse{}),
		"CreateAlertChannel":       okAnswer(&armadav1.AlertChannel{}),
		"UpdateAlertChannel":       okAnswer(&armadav1.AlertChannel{}),
		"ListAlertChannels":        okAnswer(channels),
		"DeleteAlertChannel":       okAnswer(&armadav1.DeleteAlertChannelResponse{}),
		"TestAlertChannel":         okAnswer(&armadav1.TestAlertChannelResponse{}),
	}
}

// moreCases are the cases of 17b's commands the examples do not reach.
func moreCases(h *harness) []parityCase {
	nodeStatus := func(ns ...*armadav1.NodeStatus) []answer {
		return okAnswer(&armadav1.StatusResponse{Nodes: ns})
	}
	members := okAnswer(&armadav1.ListServersResponse{StateSchema: 14, Servers: []*armadav1.ServerInfo{
		{Name: "s1", ApiAddr: "10.0.0.1:7443", Member: true, Voting: true, Reachable: true, Schema: 15},
		{Name: "s2", ApiAddr: "10.0.0.2:7443", Member: true, Leader: true, Voting: true, Reachable: true, Schema: 14, Version: "v1"},
		{Name: "s3", ApiAddr: "10.0.0.3:7443", Member: true, Schema: 14},
		{Name: "s4", ApiAddr: "10.0.0.4:7443", Member: true, Voting: true, Schema: 15},
		{Name: "s5", ApiAddr: "10.0.0.5:7443"},
	}})
	private := map[string]string{"token": "s3cret-token\n", "url": "https://k:s@s3.example.com/b\n", "key": strings.Repeat("k", 40) + "\n"}
	return []parityCase{
		// volume and snapshot.
		{name: "volume list", args: []string{"volume", "list"}, answers: defaultAnswers()},
		{name: "volume list all", args: []string{"volume", "ls", "-A"}, answers: defaultAnswers()},
		{name: "volume list json", args: []string{"volume", "list", "db", "-o", "json"}, answers: defaultAnswers()},
		{name: "volume delete unconfirmed", args: []string{"volume", "delete", "db", "data"}},
		{name: "volume delete", args: []string{"volume", "rm", "db.shop", "data", "--yes"}, answers: defaultAnswers()},
		{name: "volume backup file", args: []string{"volume", "backup", "db", "data", "-o", "data.tar.gz"}, answers: defaultAnswers()},
		{name: "volume backup stdout", args: []string{"volume", "backup", "db", "data", "-o", "-", "--stop"}, answers: defaultAnswers()},
		{name: "volume backup no output", args: []string{"volume", "backup", "db", "data"}},
		{name: "volume backup exists", args: []string{"volume", "backup", "db", "data", "-o", "key.pem"}, files: exampleFiles},
		{name: "volume backup fails", args: []string{"volume", "backup", "db", "data", "-o", "out.tgz"}, answers: with(map[string][]answer{
			"BackupVolume": streamAnswer(codes.FailedPrecondition, "the app\x1b runs nowhere", &armadav1.VolumeData{Data: []byte("x")})})},
		{name: "volume backup cut", args: []string{"volume", "backup", "db", "data", "-o", "out.tgz"}, answers: with(map[string][]answer{
			"BackupVolume": streamAnswer(codes.OK, "", &armadav1.VolumeData{Data: []byte("x")})})},
		{name: "volume restore file", args: []string{"volume", "restore", "db", "data", "key.pem", "--node", "node2"}, files: exampleFiles, answers: defaultAnswers()},
		{name: "volume restore stdin", args: []string{"volume", "restore", "db", "data", "-"}, stdin: strings.Repeat("archive bytes ", 10000), answers: defaultAnswers()},
		{name: "volume restore missing file", args: []string{"volume", "restore", "db", "data", "nope.tgz"}},
		{name: "volume restore directory", args: []string{"volume", "restore", "db", "data", "home"}, answers: defaultAnswers()},
		{name: "volume restore refused", args: []string{"volume", "restore", "db", "data", "-"}, stdin: "x", answers: with(map[string][]answer{"RestoreVolume": failAnswer(codes.FailedPrecondition, "node1 is connected")})},
		{name: "volume restore both", args: []string{"volume", "restore", "db", "data", "f", "--snapshot", "latest"}},
		{name: "volume restore neither", args: []string{"volume", "restore", "db", "data"}},
		{name: "volume restore too many", args: []string{"volume", "restore", "db", "data", "f", "g"}},
		{name: "snapshot list json", args: []string{"snapshot", "list", "db", "data", "-o", "json"}, answers: defaultAnswers()},
		{name: "snapshot create json", args: []string{"snapshot", "create", "db", "data", "-o", "json"}, answers: defaultAnswers()},
		{name: "snapshot create fails", args: []string{"snapshots", "create", "db", "data"}, answers: with(map[string][]answer{"CreateVolumeSnapshot": failAnswer(codes.FailedPrecondition, "no backup")})},

		// domain.
		{name: "domain list all", args: []string{"domain", "list", "-A"}, answers: defaultAnswers()},
		{name: "domain list app", args: []string{"domain", "list", "--app", "api.shop", "--space", "shop"}, answers: defaultAnswers()},
		{name: "domain list app of another space", args: []string{"domain", "list", "--app", "api.prod", "--space", "shop"}},
		{name: "domain list json", args: []string{"domains", "ls", "-o", "json"}, answers: defaultAnswers()},
		{name: "domain verify json", args: []string{"domain", "verify", "www.example.com", "-o", "json"}, answers: defaultAnswers()},

		// cluster.
		{name: "cluster status json", args: []string{"cluster", "status", "-o", "json"}, answers: defaultAnswers()},
		{name: "cluster status small", args: []string{"cluster", "status"}, answers: with(map[string][]answer{"ClusterStatus": okAnswer(&armadav1.ClusterStatusResponse{Nodes: 1, NodesReady: 1,
			ControlPlaneBackup: &armadav1.ControlPlaneBackupStatus{Bucket: "b"}, Runtime: &armadav1.RuntimeProgress{},
			RuntimeMove: &armadav1.RuntimeMoveStatus{Off: true}, NetworkSwitch: &armadav1.NetworkSwitchProgress{From: "a", To: "b", Step: "move"}})})},
		{name: "cluster status held", args: []string{"cluster", "status"}, answers: with(map[string][]answer{"ClusterStatus": okAnswer(&armadav1.ClusterStatusResponse{
			RuntimeMove: &armadav1.RuntimeMoveStatus{Held: "a network switch\x07 runs"}, NetworkSwitch: &armadav1.NetworkSwitchProgress{Step: "other"}})})},
		{name: "cluster status quiet move", args: []string{"cluster", "status"}, answers: with(map[string][]answer{"ClusterStatus": okAnswer(&armadav1.ClusterStatusResponse{
			RuntimeMove: &armadav1.RuntimeMoveStatus{}})})},
		{name: "cluster show", args: []string{"cluster", "show"}, answers: defaultAnswers()},
		{name: "cluster show json", args: []string{"cluster", "show", "-o", "json"}, answers: defaultAnswers()},
		{name: "cluster show empty", args: []string{"cluster", "show"}, answers: with(map[string][]answer{"GetClusterConfig": okAnswer(&armadav1.ClusterConfig{RuntimeMoveOff: true,
			BackupBucket: "b", BackupSchedule: "0 3 * * *", NodeLostTimeoutSeconds: 1 << 40})})},
		{name: "cluster update nothing", args: []string{"cluster", "update"}},
		{name: "cluster update proxies", args: []string{"cluster", "update", "--trusted-proxies", "10.0.0.0/8,192.168.0.0/16", "--trusted-proxies", "\"a,b\",c", "--proxy-protocol", ""}, answers: defaultAnswers()},
		{name: "cluster update bad csv", args: []string{"cluster", "update", "--trusted-proxies", "a\"b"}},
		{name: "cluster update bad quote", args: []string{"cluster", "update", "--trusted-proxies", "\"a\"b"}},
		{name: "cluster update logs", args: []string{"cluster", "update", "--log-retention", "336h", "--log-max-disk", "2Gi", "--log-endpoint", "https://l.example.com", "--log-token", "-"}, stdin: "  tok\n", answers: defaultAnswers()},
		{name: "cluster update log max zero", args: []string{"cluster", "update", "--log-max-disk", "0", "--network", "plain", "--mesh-cidr", "10.9.0.0/16"}, answers: defaultAnswers()},
		{name: "cluster update bad log max", args: []string{"cluster", "update", "--log-max-disk", "lots"}},
		{name: "cluster update dns token file", args: []string{"cluster", "update", "--dns-token", "token", "--acme-ca", "letsencrypt-staging"}, files: private, answers: defaultAnswers()},
		{name: "cluster update dns token missing", args: []string{"cluster", "update", "--dns-token", "nope"}},
		{name: "cluster update restart waits", args: []string{"cluster", "update", "--metrics-port", "9100", "--tls=false"}, answers: defaultAnswers()},
		{name: "cluster update backups", args: []string{"cluster", "update", "--backup-url", "url", "--backup-key", "-", "--backup-every", "2h", "--backup-keep", "last=3, daily=7,monthly=1"},
			files: private, stdin: private["key"], answers: defaultAnswers()},
		{name: "cluster update backup schedule", args: []string{"cluster", "update", "--backup-schedule", "0 3 * * *", "--backup-keep", " 5 "}, answers: defaultAnswers()},
		{name: "cluster update backup zone", args: []string{"cluster", "update", "--backup-time-zone", "UTC"}, answers: defaultAnswers()},
		{name: "cluster update backup off", args: []string{"cluster", "update", "--backup", "none"}, answers: defaultAnswers()},
		{name: "cluster update backup bad off", args: []string{"cluster", "update", "--backup", "off"}},
		{name: "cluster update backup both plans", args: []string{"cluster", "update", "--backup-every", "1h", "--backup-schedule", "@daily"}},
		{name: "cluster update backup two stdins", args: []string{"cluster", "update", "--backup-url", "-", "--backup-key", "-"}},
		{name: "cluster update backup bad keep", args: []string{"cluster", "update", "--backup-keep", "last=x"}},
		{name: "cluster update backup unknown keep", args: []string{"cluster", "update", "--backup-keep", "yearly=1"}},
		{name: "cluster update runtime move ignored", args: []string{"cluster", "update", "--runtime-move=false"}, answers: defaultAnswers()},
		{name: "cluster update runtime move", args: []string{"cluster", "update", "--runtime-move=true", "--root-domain", ""}, answers: defaultAnswers()},
		{name: "cluster update fails", args: []string{"cluster", "update", "--root-domain", "x"}, answers: with(map[string][]answer{"SetClusterConfig": failAnswer(codes.InvalidArgument, "bad\ndomain")})},
		{name: "cluster events json", args: []string{"cluster", "events", "-o", "json", "--since", "30m"}, answers: defaultAnswers()},
		{name: "cluster events since too long", args: []string{"cluster", "events", "--since", "48h"}},
		{name: "cluster events since too short", args: []string{"cluster", "events", "--since", "10ms"}},
		{name: "cluster events fails", args: []string{"cluster", "events"}, answers: with(map[string][]answer{"Events": streamAnswer(codes.PermissionDenied, "cluster-admin only", eventInfos()[0])})},
		{name: "cluster events unreachable", args: []string{"cluster", "events"}, config: func(c *clientconfig.Config) { c.Servers = []string{"127.0.0.1:1"} }},
		{name: "app events all", args: []string{"app", "events", "-A", "-f"}, answers: defaultAnswers()},
		{name: "app events of an app", args: []string{"app", "events", "web", "--since", "5m"}, answers: defaultAnswers()},

		// node.
		{name: "node list json", args: []string{"node", "list", "-o", "json"}, answers: with(map[string][]answer{"Status": nodeStatus(nodes()...)})},
		{name: "node list", args: []string{"nodes", "ls"}, answers: with(map[string][]answer{"Status": nodeStatus(nodes()...)})},
		{name: "node show", args: []string{"node", "show", "node1"}, answers: with(map[string][]answer{"Status": nodeStatus(nodes()...)})},
		{name: "node show other", args: []string{"node", "show", "node2"}, answers: with(map[string][]answer{"Status": nodeStatus(nodes()...)})},
		{name: "node show lost", args: []string{"node", "show", "node3"}, answers: with(map[string][]answer{"Status": nodeStatus(nodes()...)})},
		{name: "node show odd runtime", args: []string{"node", "show", "n"}, answers: with(map[string][]answer{"Status": nodeStatus(&armadav1.NodeStatus{Id: "n",
			Runtime: &armadav1.RuntimeStatus{Agent: "supervisor-rust", Error: "disk\x07 full", ImagesToPull: 1}}, &armadav1.NodeStatus{Id: "m", Runtime: &armadav1.RuntimeStatus{Agent: "other\x1b"}})})},
		{name: "node show json", args: []string{"node", "show", "node2", "-o", "json"}, answers: with(map[string][]answer{"Status": nodeStatus(nodes()...)})},
		{name: "node show missing", args: []string{"node", "show", "node9"}, answers: with(map[string][]answer{"Status": nodeStatus(nodes()...)})},
		{name: "node top json", args: []string{"node", "top", "-o", "json"}, answers: defaultAnswers()},
		{name: "node label", args: []string{"node", "label", "n1", "a=b", "c-", "d=e-"}, answers: defaultAnswers()},
		{name: "node label bad", args: []string{"node", "label", "n1", "nolabel"}},
		{name: "node label reserved", args: []string{"node", "label", "n1", "armada.os=linux"}},
		{name: "node label missing", args: []string{"node", "label", "n1"}},
		{name: "node site", args: []string{"node", "site", "n1", "office"}, answers: defaultAnswers()},
		{name: "node site clear", args: []string{"node", "site", "n1", "--clear"}, answers: defaultAnswers()},
		{name: "node site both", args: []string{"node", "site", "n1", "office", "--clear"}},
		{name: "node site neither", args: []string{"node", "site", "n1"}},
		{name: "node site too many", args: []string{"node", "site", "n1", "a", "b"}},
		{name: "node relay replaced", args: []string{"node", "relay", "n1"}, answers: with(map[string][]answer{"SetNodeRelay": okAnswer(&armadav1.SetNodeRelayResponse{Replaced: []string{"n2", "n3"}})})},
		{name: "node relay clear", args: []string{"node", "relay", "n1", "--clear"}, answers: defaultAnswers()},
		{name: "node rotate-key fails", args: []string{"node", "rotate-key", "n1"}, answers: with(map[string][]answer{"RotateNodeKey": failAnswer(codes.FailedPrecondition, "n1 is not connected")})},
		{name: "node delete volumes", args: []string{"node", "delete", "node1"}, answers: defaultAnswers()},
		{name: "node delete waits", args: []string{"node", "rm", "node3"}, answers: with(map[string][]answer{"Status": {
			{msg: &armadav1.StatusResponse{Nodes: []*armadav1.NodeStatus{{Id: "node3", Replicas: 2}}}},
			{msg: &armadav1.StatusResponse{Nodes: []*armadav1.NodeStatus{{Id: "node3"}}}},
		}})},
		{name: "node delete timeout", args: []string{"node", "delete", "node3", "--wait", "1ms"}, answers: with(map[string][]answer{"Status": nodeStatus(&armadav1.NodeStatus{Id: "node3", Replicas: 2})})},
		{name: "node delete force", args: []string{"node", "delete", "node1", "--force"}, answers: defaultAnswers()},
		{name: "node join-token labels", args: []string{"node", "join-token", "--label", "a=b", "--label", "c=d", "--ttl", "90m", "--from", "203.0.113.9", "--site", "office"},
			answers: with(map[string][]answer{"CreateJoinToken": okAnswer(&armadav1.CreateJoinTokenResponse{Token: "t", CaHash: "h", JoinAddr: "203.0.113.1:7444", ExpiresAt: at(day), Version: "dev"})})},
		{name: "node join-token public", args: []string{"node", "join-token"},
			answers: with(map[string][]answer{"CreateJoinToken": okAnswer(&armadav1.CreateJoinTokenResponse{JoinAddr: "203.0.113.1:7444", Version: "v1.2.3-rc.1"})})},
		{name: "node join-token bad label", args: []string{"node", "join-token", "--label", "A=b"}},
		{name: "server join-token", args: []string{"server", "join-token", "--site", "b"}, answers: defaultAnswers()},

		// server.
		{name: "server list members", args: []string{"server", "list"}, answers: with(map[string][]answer{"ListServers": members})},
		{name: "server list json", args: []string{"server", "list", "-o", "json"}, answers: with(map[string][]answer{"ListServers": members})},
		{name: "server list same", args: []string{"server", "list"}, answers: with(map[string][]answer{"ListServers": okAnswer(&armadav1.ListServersResponse{Servers: []*armadav1.ServerInfo{
			{Name: "s1", ApiAddr: h.addr, Member: true, Leader: true, Voting: true, Reachable: true}}})})},
		{name: "server list public", args: []string{"server", "list"}, answers: with(map[string][]answer{"ListServers": okAnswer(&armadav1.ListServersResponse{Servers: []*armadav1.ServerInfo{
			{Name: "s1", ApiAddr: "8.8.8.8:7443", Member: true}}})})},
		{name: "server list bad address", args: []string{"server", "list"}, answers: with(map[string][]answer{"ListServers": okAnswer(&armadav1.ListServersResponse{Servers: []*armadav1.ServerInfo{
			{Name: "s1", ApiAddr: "s1:7443", Member: true}}})})},
		{name: "server list not ip", args: []string{"server", "list"}, answers: with(map[string][]answer{"ListServers": okAnswer(&armadav1.ListServersResponse{Servers: []*armadav1.ServerInfo{
			{Name: "s1", ApiAddr: "10.0.0.1", Member: true}}})})},
		{name: "server list args", args: []string{"server", "x"}},
		{name: "server delete", args: []string{"server", "rm", "s3"}, answers: defaultAnswers()},

		// user and service.
		{name: "user create", args: []string{"user", "create", "ana", "-o", "ana.config", "--role", "deployer", "--space", "shop", "--allow-label", "team=web", "--allow-label", "team=api", "--allow-label", "zone=a"}, answers: defaultAnswers()},
		{name: "user create ssh", args: []string{"user", "create", "ops", "-o", "ops.config", "--role", "cluster-admin", "--ssh", "ops@bastion.example.com"}, answers: with(map[string][]answer{"ListServers": members})},
		{name: "user create ssh none", args: []string{"user", "create", "ops", "-o", "ops.config", "--ssh", "bastion"}, answers: defaultAnswers()},
		{name: "user create bad ssh", args: []string{"user", "create", "ops", "-o", "ops.config", "--ssh", "-oProxyCommand=x"}},
		{name: "user create no output", args: []string{"user", "create", "ana"}},
		{name: "user create exists", args: []string{"user", "create", "ana", "-o", "key.pem"}, files: exampleFiles},
		{name: "user create bad name", args: []string{"user", "create", "a b", "-o", "x.config"}},
		{name: "user create bad label", args: []string{"user", "create", "ana", "-o", "x", "--allow-label", "team"}},
		{name: "user create space from config", args: []string{"user", "create", "ana", "-o", "ana.config", "--role", "viewer"}, config: func(c *clientconfig.Config) { c.Space = "shop" }, answers: defaultAnswers()},
		{name: "user create fails", args: []string{"user", "create", "ana", "-o", "ana.config"}, answers: with(map[string][]answer{"CreateUser": failAnswer(codes.AlreadyExists, "user ana exists")})},
		{name: "service create", args: []string{"service", "create", "ci", "--role", "deployer", "--space", "shop"}, answers: defaultAnswers()},
		{name: "service create no role", args: []string{"service", "create", "ci"}, answers: with(map[string][]answer{"CreateService": okAnswer(&armadav1.Principal{})})},
		{name: "user list json", args: []string{"user", "list", "-o", "json"}, answers: defaultAnswers()},
		{name: "service list", args: []string{"service", "list"}, answers: defaultAnswers()},
		{name: "user show", args: []string{"user", "show", "ana"}, answers: defaultAnswers()},
		{name: "user show deleted", args: []string{"user", "show", "old"}, answers: defaultAnswers()},
		{name: "user show missing", args: []string{"user", "show", "nope"}, answers: defaultAnswers()},
		{name: "service show json", args: []string{"service", "show", "ci", "-o", "json"}, answers: defaultAnswers()},
		{name: "service credentials", args: []string{"service", "credentials", "ci", "-o", "ci.config"}, answers: defaultAnswers()},
		{name: "service credentials bad name", args: []string{"service", "credentials", "c i", "-o", "ci.config"}},
		{name: "user credentials no output", args: []string{"user", "credentials", "ana"}},
		{name: "user renew", args: []string{"user", "renew"}, answers: defaultAnswers()},
		{name: "service renew of a user", args: []string{"service", "renew"}},
		{name: "user renew bad cert", args: []string{"user", "renew"}, config: func(c *clientconfig.Config) { c.Cert = "nope" }},
		{name: "user renew fails", args: []string{"user", "renew"}, answers: with(map[string][]answer{"RenewOwnCertificate": failAnswer(codes.Unauthenticated, "expired")})},
		{name: "user update clear", args: []string{"user", "update", "ana", "--clear-labels"}, answers: with(map[string][]answer{"UpdatePrincipal": okAnswer(&armadav1.Principal{})})},
		{name: "user update both", args: []string{"user", "update", "ana", "--clear-labels", "--allow-label", "a=b"}},
		{name: "user update neither", args: []string{"user", "update", "ana"}},
		{name: "service delete unconfirmed", args: []string{"service", "delete", "ci"}},
		{name: "service delete", args: []string{"service", "rm", "ci", "--yes"}, answers: defaultAnswers()},

		// role.
		{name: "role list", args: []string{"roles", "ls"}, answers: defaultAnswers()},
		{name: "role list not admin", args: []string{"role", "list"}, answers: with(map[string][]answer{"ListPrincipals": failAnswer(codes.PermissionDenied, "no")})},
		{name: "role list fails", args: []string{"role", "list"}, answers: with(map[string][]answer{"ListPrincipals": failAnswer(codes.Internal, "boom")})},
		{name: "role list json", args: []string{"role", "list", "-o", "json"}, answers: defaultAnswers()},
		{name: "role show missing", args: []string{"role", "show", "boss"}, answers: defaultAnswers()},
		{name: "role show json", args: []string{"role", "show", "viewer", "-o", "json"}, answers: defaultAnswers()},
		{name: "role grant space", args: []string{"role", "grant", "deployer", "--user", "ana", "--space", "shop"}, answers: defaultAnswers()},
		{name: "role grant default space", args: []string{"role", "grant", "viewer", "--service", "ci", "--space", "default"}, answers: defaultAnswers()},
		{name: "role grant saved space", args: []string{"role", "grant", "viewer", "--service", "ci"}, env: map[string]string{"ARMADA_SPACE": "shop"}, answers: defaultAnswers()},
		{name: "role grant both", args: []string{"role", "grant", "viewer", "--service", "ci", "--user", "ana"}},
		{name: "role grant neither", args: []string{"role", "grant", "viewer"}},
		{name: "role revoke", args: []string{"role", "revoke", "deployer", "--user", "ana", "--space", "shop"}, answers: defaultAnswers()},

		// metrics.
		{name: "metrics credentials", args: []string{"metrics", "credentials", "prometheus"}, answers: defaultAnswers()},
		{name: "metrics credentials output", args: []string{"metrics", "credentials", "prom", "-o", "certs"}, answers: defaultAnswers()},
		{name: "metrics credentials exists", args: []string{"metrics", "credentials", "prom", "-o", "home"}},
		{name: "metrics credentials bad name", args: []string{"metrics", "credentials", "a:b"}},
		{name: "metrics credentials fails", args: []string{"metrics", "credentials", "prom"}, answers: with(map[string][]answer{"IssueMetricsCertificate": failAnswer(codes.PermissionDenied, "no")})},
		{name: "metrics credentials no config", args: []string{"metrics", "credentials", "prom"}, noConfig: true},
		{name: "metrics list json", args: []string{"metrics", "ls", "-o", "json"}, answers: defaultAnswers()},
		{name: "metrics revoke unconfirmed", args: []string{"metrics", "revoke", "prom"}},
		{name: "metrics args", args: []string{"metrics", "x"}},

		// alert.
		{name: "alert create", args: []string{"alert", "create", "ops", "--type", "slack", "--url", "-", "--space", "shop,billing", "--reason", "Crashed", "--reason", "OutOfMemory"}, stdin: "https://hooks.example.com/x\n", answers: defaultAnswers()},
		{name: "alert create email", args: []string{"alert", "create", "mail", "--type", "email", "--smtp-host", "smtp.example.com:587", "--smtp-user", "u", "--password", "token", "--from", "a@example.com", "--to", "b@example.com,c@example.com"}, files: private, answers: defaultAnswers()},
		{name: "alert create no type", args: []string{"alert", "create", "ops"}, answers: defaultAnswers()},
		{name: "alert create two secrets", args: []string{"alert", "create", "ops", "--type", "slack", "--url", "-", "--token", "-"}},
		{name: "alert create secret missing", args: []string{"alert", "create", "ops", "--type", "slack", "--url", "nope"}},
		{name: "alert create invalid space env", args: []string{"alert", "create", "ops", "--type", "slack"}, env: map[string]string{"ARMADA_SPACE": "Bad_Space"}},
		{name: "alert update", args: []string{"alert", "update", "ops", "--reason", "", "--chat-id", "-100"}, answers: defaultAnswers()},
		{name: "alert update nothing", args: []string{"alert", "update", "ops"}, answers: defaultAnswers()},
		{name: "alert list json", args: []string{"alert", "list", "-o", "json"}, answers: defaultAnswers()},
		{name: "alert test fails", args: []string{"alert", "test", "ops"}, answers: with(map[string][]answer{"TestAlertChannel": failAnswer(codes.Unavailable, "slack said 404")})},

		// app logs and job logs.
		{name: "app logs", args: []string{"app", "logs", "web"}, answers: defaultAnswers()},
		{name: "app logs replica", args: []string{"app", "logs", "web", "--replica", "k3p9x", "--timestamps", "--tail", "-5", "--container", "log-ship", "--grep", "GET"}, answers: defaultAnswers()},
		{name: "app logs history", args: []string{"app", "logs", "web", "--since", "2h", "--until", "30m", "--limit", "200000", "--tail", "20000"}, answers: defaultAnswers()},
		{name: "app logs days", args: []string{"app", "logs", "web", "--since", "3d"}, answers: defaultAnswers()},
		{name: "app logs since time", args: []string{"app", "logs", "web", "--since", "2026-11-13T09:00:00+07:00", "--until", "2026-11-13T10:00:00.5Z"}, answers: defaultAnswers()},
		{name: "app logs bad since", args: []string{"app", "logs", "web", "--since", "yesterday"}},
		{name: "app logs bad days", args: []string{"app", "logs", "web", "--since", "9999d"}},
		{name: "app logs negative", args: []string{"app", "logs", "web", "--since", "-2h"}},
		{name: "app logs bad until", args: []string{"app", "logs", "web", "--since", "1h", "--until", "2026-02-30T00:00:00Z"}},
		{name: "app logs until without since", args: []string{"app", "logs", "web", "--until", "1h"}},
		{name: "app logs limit without since", args: []string{"app", "logs", "web", "--limit", "5"}},
		{name: "app logs fails", args: []string{"app", "logs", "web", "-f"}, answers: with(map[string][]answer{"Logs": streamAnswer(codes.NotFound, "replica k3 not found; the replicas: a, b", logEntries()[0])})},
		{name: "job logs", args: []string{"job", "logs", "migrate", "--run", "12", "--task", "70000000"}, answers: defaultAnswers()},
		{name: "job logs history", args: []string{"job", "logs", "migrate", "--since", "1h", "--task", "-3"}, answers: defaultAnswers()},

		// app exec.
		{name: "app exec", args: []string{"app", "exec", "web", "--", "env"}, answers: defaultAnswers()},
		{name: "app exec exit code", args: []string{"app", "exec", "web", "--replica", "k3p9x", "--container", "log-ship", "--", "sh", "-c", "exit 3"}, answers: with(map[string][]answer{"Exec": execAnswer(3, stdout("out"))})},
		{name: "app exec stdin", args: []string{"app", "exec", "web", "-i", "--", "cat"}, stdin: "line one\nline two\n", answers: with(map[string][]answer{"Exec": {{stream: []proto.Message{
			&armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_Replica{Replica: "web-r2-k3p9x"}}, nil, stdout("line one\nline two\n"),
			&armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_ExitCode{ExitCode: 0}}}}}})},
		{name: "app exec tty without terminal", args: []string{"app", "exec", "web", "-t"}},
		{name: "app exec no dash", args: []string{"app", "exec", "web", "ls", "-l"}},
		{name: "app exec two apps", args: []string{"app", "exec", "web", "api", "--", "ls"}},
		{name: "app exec no app", args: []string{"app", "exec", "--", "ls"}},
		{name: "app exec missing app", args: []string{"app", "exec"}},
		{name: "app exec empty command", args: []string{"app", "exec", "web", "--", ""}},
		{name: "app exec long argument", args: []string{"app", "exec", "web", "--", "echo", strings.Repeat("x", 5000)}},
		{name: "app exec not started", args: []string{"app", "exec", "web"}, answers: with(map[string][]answer{"Exec": streamAnswer(codes.OK, "", stdout("x"))})},
		{name: "app exec refused", args: []string{"app", "exec", "web"}, answers: with(map[string][]answer{"Exec": streamAnswer(codes.NotFound, "no ready replica of web")})},
		{name: "app exec no exit code", args: []string{"app", "exec", "web"}, answers: with(map[string][]answer{"Exec": streamAnswer(codes.OK, "",
			&armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_Replica{Replica: "r"}}, stderr("partial"))})},
		{name: "app exec ends with error", args: []string{"app", "exec", "web"}, answers: with(map[string][]answer{"Exec": streamAnswer(codes.Unavailable, "node lost",
			&armadav1.ExecServerMessage{Msg: &armadav1.ExecServerMessage_Replica{Replica: "r"}})})},

		// app top.
		{name: "app top", args: []string{"app", "top"}, answers: defaultAnswers()},
		{name: "app top all", args: []string{"app", "top", "-A"}, answers: defaultAnswers()},
		{name: "app top app", args: []string{"app", "top", "web"}, answers: defaultAnswers()},
		{name: "app top spaces json", args: []string{"app", "top", "--spaces", "-o", "json"}, answers: defaultAnswers()},
		{name: "app top json", args: []string{"app", "top", "-o", "json"}, answers: defaultAnswers()},
		{name: "app top spaces and app", args: []string{"app", "top", "web", "--spaces"}},

		// completion of 17b's names.
		{name: "complete nodes", args: []string{"__complete", "node", "show", ""}, answers: with(map[string][]answer{"Status": nodeStatus(nodes()...)})},
		{name: "complete node flag", args: []string{"__complete", "cluster", "events", "--node", "n"}, answers: with(map[string][]answer{"Status": nodeStatus(nodes()...)})},
		{name: "complete volumes", args: []string{"__complete", "volume", "delete", "db", ""}, answers: defaultAnswers()},
		{name: "complete replicas", args: []string{"__complete", "app", "exec", "web", "--replica", ""}, answers: defaultAnswers()},
		{name: "complete containers", args: []string{"__complete", "app", "logs", "web", "--container", ""}, answers: defaultAnswers()},
		{name: "complete roles", args: []string{"__complete", "role", "show", ""}, answers: defaultAnswers()},
		{name: "complete role flag", args: []string{"__complete", "user", "create", "x", "--role", ""}, answers: defaultAnswers()},
		{name: "complete users", args: []string{"__complete", "user", "show", ""}, answers: defaultAnswers()},
		{name: "complete user flag", args: []string{"__complete", "role", "grant", "viewer", "--user", ""}, answers: defaultAnswers()},
		{name: "complete services", args: []string{"__complete", "service", "delete", ""}, answers: defaultAnswers()},
		{name: "complete alerts", args: []string{"__complete", "alert", "test", ""}, answers: defaultAnswers()},
		{name: "complete alert spaces", args: []string{"__complete", "alert", "update", "ops", "--space", ""}, answers: defaultAnswers()},
		{name: "complete metrics", args: []string{"__complete", "metrics", "revoke", ""}, answers: defaultAnswers()},
		{name: "complete domains", args: []string{"__complete", "domain", "verify", ""}, answers: defaultAnswers()},
		{name: "complete slice flags", args: []string{"__complete", "cluster", "update", "--trusted-proxies", "a", "--t"}},
	}
}
