package server

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/etcd"
	"github.com/ryanbekhen/armada/internal/pki"
	"github.com/ryanbekhen/armada/internal/secrets"
	"github.com/ryanbekhen/armada/internal/spec"
	"github.com/ryanbekhen/armada/internal/store"
)

// Scenarios of the Rust control plane's core (ADR 0055, pull request 8),
// run against both servers by runParity. Each records what a test of
// this package checks, so the two servers must give the same answers.

// parityPorted are the AdminService methods the Rust server answers
// itself; the others answer Unimplemented until their pull request.
var parityPorted = map[string]bool{
	"GetClusterConfig": true, "SetClusterConfig": true, "CreateJoinToken": true, "CordonNode": true,
	"LabelNode": true, "RestrictNode": true, "SetNodeSite": true, "SetNodeRelay": true, "RotateNodeKey": true,
	"RemoveNode": true, "ListServers": true, "RemoveServer": true, "CreateSpace": true, "ListSpaces": true,
	"DeleteSpace": true, "UpdateSpace": true, "CreateUser": true, "IssueUserCertificate": true,
	"CreateService": true, "IssueServiceCertificate": true, "ListPrincipals": true, "UpdatePrincipal": true,
	"DeletePrincipal": true, "CreateAssignment": true, "DeleteAssignment": true, "ListRoles": true,
	"RenewOwnCertificate": true, "Events": true,
}

// callAny calls a method of the API with an empty request, as any client
// could, and returns its error (nil once it answered).
func callAny(sc *scenario, conn *grpc.ClientConn, m protoreflect.MethodDescriptor) error {
	full := "/" + string(m.Parent().FullName()) + "/" + string(m.Name())
	in := dynamicpb.NewMessage(m.Input())
	out := dynamicpb.NewMessage(m.Output())
	if !m.IsStreamingClient() && !m.IsStreamingServer() {
		return conn.Invoke(sc.ctx, full, in, out)
	}
	s, err := conn.NewStream(sc.ctx, &grpc.StreamDesc{ServerStreams: m.IsStreamingServer(), ClientStreams: m.IsStreamingClient()}, full)
	if err != nil {
		return err
	}
	_ = s.SendMsg(in)
	_ = s.CloseSend()
	err = s.RecvMsg(out)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func TestParityMethodAccess(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		if _, err := sc.st.CreateSpace(sc.ctx, "team", "user:ryan", nil); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"vera", "dana", "sam"} {
			if _, err := sc.st.CreateUser(sc.ctx, store.Principal{Name: name, Since: sc.clock.now().Add(-time.Hour)}, "user:ryan"); err != nil {
				t.Fatal(err)
			}
		}
		for name, g := range map[string]store.Grant{"vera": {Role: store.RoleViewer, Space: "team"}, "dana": {Role: store.RoleDeployer, Space: "team"}, "sam": {Role: store.RoleSpaceCreator}} {
			if _, err := sc.st.Assign(sc.ctx, store.KindUser, name, g, "user:ryan"); err != nil {
				t.Fatal(err)
			}
		}
		if err := sc.st.UpsertNode(sc.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.11"}); err != nil {
			t.Fatal(err)
		}
		callers := []struct {
			label string
			conn  *grpc.ClientConn
		}{
			{"vera", sc.dial(pki.Identity{Kind: pki.KindUser, Name: "vera"})},
			{"dana", sc.dial(pki.Identity{Kind: pki.KindUser, Name: "dana"})},
			{"sam", sc.dial(pki.Identity{Kind: pki.KindUser, Name: "sam"})},
			// A user the cluster has no record of, signed after its keyspace
			// was made: refused.
			{"stranger", sc.dial(pki.Identity{Kind: pki.KindUser, Name: "stranger"})},
			{"node", sc.dial(pki.Identity{Kind: pki.KindNode, Name: "n1"})},
			{"service", sc.dial(pki.Identity{Kind: pki.KindService, Name: "nobody"})},
			{"metrics", sc.dial(pki.Identity{Kind: pki.KindMetrics, Name: "prom"})},
		}
		services := armadav1.File_armada_v1_armada_proto.Services()
		for _, svc := range []string{"AdminService", "AgentService"} {
			ms := services.ByName(protoreflect.Name(svc)).Methods()
			for i := range ms.Len() {
				m := ms.Get(i)
				for _, c := range callers {
					err := callAny(sc, c.conn, m)
					label := c.label + " " + svc + "/" + string(m.Name())
					code := status.Code(err)
					msg := status.Convert(err).Message()
					// The interceptor's refusals; a handler's own checks of
					// spaces come with the handlers.
					refused := (code == codes.PermissionDenied || code == codes.Unauthenticated) &&
						(strings.Contains(msg, " may not call ") || strings.Contains(msg, "has no role that allows") ||
							strings.HasPrefix(msg, "certificate of ") || strings.Contains(msg, "client certificate"))
					switch {
					case refused:
						sc.note(label, err)
					case svc == "AdminService" && parityPorted[string(m.Name())]:
						if err != nil {
							sc.note(label, err)
						} else {
							sc.note(label, "answered")
						}
					default:
						// Reached a handler this pull request does not port.
						sc.note(label, "reached the handler")
					}
				}
			}
		}
	})
}

func TestParityServersHeader(t *testing.T) {
	fc := parityConfig{cluster: true}
	runParity(t, fc, func(sc *scenario) {
		var md metadata.MD
		resp, err := sc.admin.ListServers(sc.ctx, &armadav1.ListServersRequest{}, grpc.Header(&md))
		sc.answer("list servers", resp, err)
		sc.note("header", md.Get("armada-servers"))
		sc.fc.mu.Lock()
		sc.fc.members = append(sc.fc.members, etcdMember(101, "cp-2", true))
		sc.fc.mu.Unlock()
		if err := sc.st.UpsertServer(sc.ctx, store.Server{Name: "cp-2", PrivateIP: "10.0.0.2", APIAddr: "10.0.0.2:7443", MemberID: 101, Schema: 15, Version: "v1"}); err != nil {
			t.Fatal(err)
		}
		resp, err = sc.admin.ListServers(sc.ctx, &armadav1.ListServersRequest{})
		sc.answer("list servers with a learner", resp, err)
		sc.sut.reconcile(sc.t)
		resp, err = sc.admin.ListServers(sc.ctx, &armadav1.ListServersRequest{})
		sc.answer("list servers after promotion", resp, err)
		_, err = sc.admin.RemoveServer(sc.ctx, &armadav1.RemoveServerRequest{Name: "cp-1"})
		sc.note("remove the leader", err)
		_, err = sc.admin.RemoveServer(sc.ctx, &armadav1.RemoveServerRequest{Name: "cp-9"})
		sc.note("remove an unknown server", err)
		_, err = sc.admin.RemoveServer(sc.ctx, &armadav1.RemoveServerRequest{Name: "cp-2"})
		sc.note("remove cp-2", err)
		resp, err = sc.admin.ListServers(sc.ctx, &armadav1.ListServersRequest{})
		sc.answer("list servers after removal", resp, err)
		sc.keyspace("keyspace")
	})
}

func TestParityRBAC(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		csr := func(kind, name string) []byte {
			_, c, err := pki.NewCSR(pki.Identity{Kind: kind, Name: name})
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
		roles, err := sc.admin.ListRoles(sc.ctx, &armadav1.ListRolesRequest{})
		sc.answer("roles", roles, err)
		for _, req := range []*armadav1.CreateUserRequest{
			{Name: "ryan", Csr: csr(pki.KindUser, "ryan")},
			{Name: "bad name!", Csr: csr(pki.KindUser, "x")},
			{Name: "erin", Csr: csr(pki.KindUser, "erin"), Roles: []*armadav1.RoleAssignment{{Role: "viewer", Space: "default"}}},
			{Name: "erin", Csr: csr(pki.KindUser, "erin"), Roles: []*armadav1.RoleAssignment{{Role: "cluster-admin", Space: "x"}}},
			{Name: "erin", Csr: []byte("nope")},
			{Name: "erin", Csr: csr(pki.KindUser, "erin"), Roles: []*armadav1.RoleAssignment{{Role: "viewer"}},
				Labels: []*armadav1.LabelAllowance{{Key: "disk", Values: []string{"ssd"}}}},
			{Name: "erin", Csr: csr(pki.KindUser, "erin")},
		} {
			resp, err := sc.admin.CreateUser(sc.ctx, req)
			sc.answer("create user "+req.Name, resp, err)
		}
		for _, req := range []*armadav1.CreateServiceRequest{
			{Name: "ci", Roles: []*armadav1.RoleAssignment{{Role: "deployer", Space: "default"}}},
			{Name: "ci"},
			{Name: "Bad"},
		} {
			resp, err := sc.admin.CreateService(sc.ctx, req)
			sc.answer("create service "+req.Name, resp, err)
		}
		cert, err := sc.admin.IssueServiceCertificate(sc.ctx, &armadav1.IssuePrincipalCertificateRequest{Name: "ci", Csr: csr(pki.KindService, "ci")})
		sc.answer("issue service certificate", cert, err)
		_, err = sc.admin.IssueServiceCertificate(sc.ctx, &armadav1.IssuePrincipalCertificateRequest{Name: "nope", Csr: csr(pki.KindService, "nope")})
		sc.note("issue for an unknown service", err)
		uc, err := sc.admin.IssueUserCertificate(sc.ctx, &armadav1.IssuePrincipalCertificateRequest{Name: "erin", Csr: csr(pki.KindUser, "erin")})
		sc.answer("issue user certificate", uc, err)
		_, err = sc.admin.IssueUserCertificate(sc.ctx, &armadav1.IssuePrincipalCertificateRequest{Name: "ryan", Csr: csr(pki.KindUser, "ryan")})
		sc.note("issue own certificate", err)
		for _, req := range []*armadav1.AssignmentRequest{
			{Kind: "user", Name: "erin", Role: &armadav1.RoleAssignment{Role: "deployer", Space: "default"}},
			{Kind: "user", Name: "erin", Role: &armadav1.RoleAssignment{Role: "deployer", Space: "default"}},
			{Kind: "user", Name: "erin", Role: &armadav1.RoleAssignment{Role: "space-creator"}},
			{Kind: "service", Name: "ci", Role: &armadav1.RoleAssignment{Role: "admin", Space: "default"}},
			{Kind: "user", Name: "nobody", Role: &armadav1.RoleAssignment{Role: "viewer"}},
			{Kind: "group", Name: "erin", Role: &armadav1.RoleAssignment{Role: "viewer"}},
		} {
			p, err := sc.admin.CreateAssignment(sc.ctx, req)
			sc.answer("assign "+req.Name, p, err)
		}
		for _, req := range []*armadav1.AssignmentRequest{
			{Kind: "user", Name: "erin", Role: &armadav1.RoleAssignment{Role: "space-creator"}},
			{Kind: "user", Name: "ryan", Role: &armadav1.RoleAssignment{Role: "cluster-admin"}},
		} {
			p, err := sc.admin.DeleteAssignment(sc.ctx, req)
			sc.answer("unassign "+req.Name, p, err)
		}
		p, err := sc.admin.UpdatePrincipal(sc.ctx, &armadav1.UpdatePrincipalRequest{Kind: "service", Name: "ci", Labels: []*armadav1.LabelAllowance{{Key: "zone", Values: []string{"a", "b"}}}})
		sc.answer("update ci", p, err)
		list, err := sc.admin.ListPrincipals(sc.ctx, &armadav1.ListPrincipalsRequest{})
		sc.answer("list principals", list, err)
		_, err = sc.admin.ListPrincipals(sc.ctx, &armadav1.ListPrincipalsRequest{Kind: "group"})
		sc.note("list groups", err)
		sc.keyspace("keyspace after creating")

		// Renewing one's own certificate, as a user and as a service.
		erinKey, erinCSR, err := pki.NewCSR(pki.Identity{Kind: pki.KindUser, Name: "erin"})
		if err != nil {
			t.Fatal(err)
		}
		_ = erinKey
		erin := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "erin"})
		renewed, err := erin.RenewOwnCertificate(sc.ctx, &armadav1.RenewOwnCertificateRequest{Csr: erinCSR})
		sc.note("erin renews with a certificate signed before her record", err)
		_ = renewed
		ciConn := sc.dialPEM(mustIssue(t, sc.fx.ca, pki.Identity{Kind: pki.KindService, Name: "ci"}))
		ci := armadav1.NewAdminServiceClient(ciConn)
		r2, err := ci.RenewOwnCertificate(sc.ctx, &armadav1.RenewOwnCertificateRequest{Csr: csr(pki.KindService, "ci")})
		sc.note("unrecorded service certificate renews", err)
		_ = r2
		_, err = sc.admin.DeletePrincipal(sc.ctx, &armadav1.DeletePrincipalRequest{Kind: "user", Name: "ryan"})
		sc.note("delete self", err)
		_, err = sc.admin.DeletePrincipal(sc.ctx, &armadav1.DeletePrincipalRequest{Kind: "user", Name: "erin"})
		sc.note("delete erin", err)
		_, err = sc.admin.DeletePrincipal(sc.ctx, &armadav1.DeletePrincipalRequest{Kind: "service", Name: "ci"})
		sc.note("delete ci", err)
		list, err = sc.admin.ListPrincipals(sc.ctx, &armadav1.ListPrincipalsRequest{Kind: "user"})
		sc.answer("list users", list, err)
		sc.keyspace("keyspace after deleting")
	})
}

func mustIssue(t *testing.T, ca *pki.CA, id pki.Identity) ([]byte, []byte) {
	t.Helper()
	c, k, err := ca.Issue(pki.IssueRequest{Identity: id, Client: true})
	if err != nil {
		t.Fatal(err)
	}
	return c, k
}

func TestParitySpaces(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		if _, err := sc.st.CreateUser(sc.ctx, store.Principal{Name: "sam", Since: sc.clock.now().Add(-time.Hour)}, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.st.Assign(sc.ctx, store.KindUser, "sam", store.Grant{Role: store.RoleSpaceCreator}, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		sam := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "sam"})
		for _, name := range []string{"team", "team", "Bad", "default"} {
			info, err := sc.admin.CreateSpace(sc.ctx, &armadav1.CreateSpaceRequest{Name: name})
			sc.answer("admin creates "+name, info, err)
		}
		info, err := sam.CreateSpace(sc.ctx, &armadav1.CreateSpaceRequest{Name: "sams"})
		sc.answer("sam creates sams", info, err)
		l, err := sam.ListSpaces(sc.ctx, &armadav1.ListSpacesRequest{})
		sc.answer("sam lists", l, err)
		l, err = sc.admin.ListSpaces(sc.ctx, &armadav1.ListSpacesRequest{})
		sc.answer("admin lists", l, err)
		on, off := true, false
		for _, req := range []*armadav1.UpdateSpaceRequest{
			{NetworkIsolation: &on}, {Name: "team", NetworkIsolation: &off}, {Name: "nope", NetworkIsolation: &on}, {Name: "team"},
		} {
			info, err := sc.admin.UpdateSpace(sc.ctx, req)
			sc.answer("update "+req.Name, info, err)
		}
		_, err = sam.UpdateSpace(sc.ctx, &armadav1.UpdateSpaceRequest{Name: "sams"})
		sc.note("sam updates", err)
		_, err = sam.DeleteSpace(sc.ctx, &armadav1.DeleteSpaceRequest{Name: "team"})
		sc.note("sam deletes team", err)
		_, err = sam.DeleteSpace(sc.ctx, &armadav1.DeleteSpaceRequest{Name: "sams"})
		sc.note("sam deletes sams", err)
		_, err = sc.admin.DeleteSpace(sc.ctx, &armadav1.DeleteSpaceRequest{Name: "default"})
		sc.note("admin deletes default", err)
		sc.keyspace("keyspace")
	})
}

func TestParitySettings(t *testing.T) {
	runParity(t, parityConfig{masterKey: true}, func(sc *scenario) {
		cc, err := sc.admin.GetClusterConfig(sc.ctx, &armadav1.GetClusterConfigRequest{})
		sc.answer("initial", cc, err)
		for _, req := range []*armadav1.SetClusterConfigRequest{
			{SetRootDomain: true, Config: &armadav1.ClusterConfig{RootDomain: " Apps.Example.COM "}},
			{SetRootDomain: true, Config: &armadav1.ClusterConfig{RootDomain: "bad_domain"}},
			{SetAcmeEmail: true, Config: &armadav1.ClusterConfig{AcmeEmail: "no-at-sign"}},
			{SetAcmeCa: true, Config: &armadav1.ClusterConfig{AcmeCa: "http://insecure.example"}},
			{SetDnsProvider: true, Config: &armadav1.ClusterConfig{DnsProvider: "route53"}},
			{SetDnsProvider: true, Config: &armadav1.ClusterConfig{DnsProvider: "cloudflare"}},
			{SetNodeLostTimeout: true, Config: &armadav1.ClusterConfig{NodeLostTimeoutSeconds: 5}},
			{SetMetricsPort: true, Config: &armadav1.ClusterConfig{MetricsPort: 70000}},
			{SetTls: true, SetAcmeEmail: true, SetAcmeCa: true, SetMetricsPort: true, SetNodeLostTimeout: true,
				Config: &armadav1.ClusterConfig{Tls: true, AcmeEmail: " ops@example.com ", AcmeCa: "letsencrypt-staging", MetricsPort: 9100, NodeLostTimeoutSeconds: 90}},
			{SetDnsProvider: true, SetDnsToken: true, DnsToken: []byte("  token-value \n"), Config: &armadav1.ClusterConfig{DnsProvider: "cloudflare"}},
			{SetDnsToken: true, DnsToken: []byte("two\nlines")},
			{SetDnsProvider: true, Config: &armadav1.ClusterConfig{DnsProvider: "none"}},
		} {
			cc, err := sc.admin.SetClusterConfig(sc.ctx, req)
			b, _ := json.Marshal(req.GetConfig())
			sc.answer("set "+string(b), cc, err)
		}
		sc.eventually("settings changes told", func() bool { return sc.sut.settingsChanged() == 3 })
		sc.note("settings changed", sc.sut.settingsChanged())
		set, err := LoadSettings(sc.ctx, sc.st)
		if err != nil {
			t.Fatal(err)
		}
		tok, ok, err := set.Token(sc.fx.keys)
		if err != nil || !ok || string(tok.Bytes()) != "token-value" {
			t.Errorf("token %v %v", ok, err)
		}
		sc.keyspace("keyspace")
	})
}

func etcdMember(id uint64, name string, learner bool) etcdMemberInfo {
	return etcdMemberInfo{ID: id, Name: name, Learner: learner}
}

func TestParityJoin(t *testing.T) {
	runParity(t, parityConfig{join: true, joinBurst: 100}, func(sc *scenario) {
		if err := sc.st.UpsertNode(sc.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.11"}); err != nil {
			t.Fatal(err)
		}
		for _, req := range []*armadav1.CreateJoinTokenRequest{
			{TtlSeconds: 30}, {TtlSeconds: 90000}, {From: "8.8.8.8"}, {Site: "Bad Site"}, {Site: "far"},
			{Labels: map[string]string{"armada.os": "linux"}}, {Server: true},
		} {
			resp, err := sc.admin.CreateJoinToken(sc.ctx, req)
			b, _ := json.Marshal(req)
			sc.answer("token "+string(b), resp, err)
		}
		tok, err := sc.admin.CreateJoinToken(sc.ctx, &armadav1.CreateJoinTokenRequest{Labels: map[string]string{"disk": "ssd"}})
		if err != nil {
			t.Fatal(err)
		}
		id, _, _ := strings.Cut(tok.Token, ".")
		sc.alias(id, "<token>")
		sc.alias(tok.Token, "<token>.<secret>")
		sc.answer("token", tok, nil)
		sc.keyspace("keyspace with a token")
		jc := sc.joinClient(tok)
		bad := tok.Token[:len(tok.Token)-1] + "0"
		if strings.HasSuffix(tok.Token, "0") {
			bad = tok.Token[:len(tok.Token)-1] + "1"
		}
		for _, c := range []struct {
			name string
			mod  func(*armadav1.JoinRequest)
		}{
			{"wrong secret", func(r *armadav1.JoinRequest) { _, r.TokenSecret, _ = strings.Cut(bad, ".") }},
			{"unknown token", func(r *armadav1.JoinRequest) { r.TokenId = "000000000000" }},
			{"malformed", func(r *armadav1.JoinRequest) { r.TokenSecret = "x" }},
			{"public IP", func(r *armadav1.JoinRequest) { r.PrivateIp = "8.8.8.8" }},
			{"bad node name", func(r *armadav1.JoinRequest) { r.NodeName = "../etc" }},
			{"taken name", func(r *armadav1.JoinRequest) { r.NodeName = "n1" }},
			{"taken IP", func(r *armadav1.JoinRequest) { r.PrivateIp = "10.0.0.11" }},
			{"loopback IP", func(r *armadav1.JoinRequest) { r.PrivateIp = "127.0.0.1" }},
			{"zoned IP", func(r *armadav1.JoinRequest) { r.PrivateIp = "fd00::1%x" }},
			{"no CSR", func(r *armadav1.JoinRequest) { r.Csr = nil }},
			{"garbage CSR", func(r *armadav1.JoinRequest) { r.Csr = []byte("nope") }},
			{"oversized CSR", func(r *armadav1.JoinRequest) { r.Csr = make([]byte, 5000) }},
			{"behind NAT with an endpoint", func(r *armadav1.JoinRequest) { r.BehindNat, r.Endpoint = true, "8.8.8.8" }},
		} {
			req, _ := joinReq(t, tok.Token, "n2", "10.0.0.12")
			c.mod(req)
			_, err := jc.Join(sc.ctx, req)
			sc.note("join: "+c.name, err)
		}
		req, _ := joinReq(t, tok.Token, "n2", "10.0.0.12")
		req.Version = "v9"
		resp, err := jc.Join(sc.ctx, req)
		sc.answer("join n2", resp, err)
		again, _ := joinReq(t, tok.Token, "n3", "10.0.0.13")
		_, err = jc.Join(sc.ctx, again)
		sc.note("token reused", err)
		sc.keyspace("keyspace after the join")

		// The listener serves only joining.
		main := armadav1.NewAdminServiceClient(sc.dialJoinAsAPI(tok))
		_, err = main.ListServers(sc.ctx, &armadav1.ListServersRequest{})
		sc.note("API on the join listener", err)
	})
}

// dialJoinAsAPI reaches the join listener as an API client would.
func (sc *scenario) dialJoinAsAPI(tok *armadav1.CreateJoinTokenResponse) *grpc.ClientConn {
	pin, _ := pki.ParseCAHash(tok.CaHash)
	ca, err := pki.FetchPinnedCA(sc.ctx, tok.JoinAddr, pin)
	if err != nil {
		sc.t.Fatal(err)
	}
	conn, err := grpc.NewClient(tok.JoinAddr, grpc.WithTransportCredentials(credentialsJoin(ca)))
	if err != nil {
		sc.t.Fatal(err)
	}
	sc.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestParityJoinRateLimit(t *testing.T) {
	runParity(t, parityConfig{join: true}, func(sc *scenario) {
		tok, err := sc.admin.CreateJoinToken(sc.ctx, &armadav1.CreateJoinTokenRequest{})
		if err != nil {
			t.Fatal(err)
		}
		jc := sc.joinClient(tok)
		for i := range 7 {
			req, _ := joinReq(t, tok.Token, "n2", "8.8.8.8")
			_, err := jc.Join(sc.ctx, req)
			sc.note("attempt "+string(rune('0'+i)), err)
		}
	})
}

func TestParityJoinServer(t *testing.T) {
	runParity(t, parityConfig{join: true, masterKey: true, cluster: true, joinBurst: 100}, func(sc *scenario) {
		_, err := sc.admin.CreateJoinToken(sc.ctx, &armadav1.CreateJoinTokenRequest{Server: true, TtlSeconds: 7200})
		sc.note("2h server token", err)
		nodeTok, err := sc.admin.CreateJoinToken(sc.ctx, &armadav1.CreateJoinTokenRequest{})
		if err != nil {
			t.Fatal(err)
		}
		tok, err := sc.admin.CreateJoinToken(sc.ctx, &armadav1.CreateJoinTokenRequest{Server: true, TtlSeconds: 600})
		if err != nil {
			t.Fatal(err)
		}
		for i, tk := range []string{nodeTok.Token, tok.Token} {
			id, _, _ := strings.Cut(tk, ".")
			sc.alias(id, []string{"<node token>", "<server token>"}[i])
		}
		jc := sc.joinClient(tok)
		_, err = jc.JoinServer(sc.ctx, joinServerReq(t, nodeTok.Token, "cp-2", "10.0.0.2"))
		sc.note("server with a node token", err)
		nreq, _ := joinReq(t, tok.Token, "n9", "10.0.0.9")
		_, err = jc.Join(sc.ctx, nreq)
		sc.note("node with a server token", err)
		for _, c := range []struct {
			name string
			mod  func(*armadav1.JoinServerRequest)
		}{
			{"public IP", func(r *armadav1.JoinServerRequest) { r.PrivateIp = "8.8.8.8" }},
			{"bad name", func(r *armadav1.JoinServerRequest) { r.Name = "../x" }},
			{"bad port", func(r *armadav1.JoinServerRequest) { r.ApiPort = 70000 }},
			{"no etcd", func(r *armadav1.JoinServerRequest) { r.EtcdPeerPort = 0 }},
			{"no CSR", func(r *armadav1.JoinServerRequest) { r.NodeCsr = nil }},
			{"unspecified", func(r *armadav1.JoinServerRequest) { r.PrivateIp = "0.0.0.0" }},
		} {
			r := joinServerReq(t, tok.Token, "cp-2", "10.0.0.2")
			c.mod(r)
			_, err := jc.JoinServer(sc.ctx, r)
			sc.note("join server: "+c.name, err)
		}
		req := joinServerReq(t, tok.Token, "cp-2", "10.0.0.2")
		req.UserName = "joiner"
		resp, err := jc.JoinServer(sc.ctx, req)
		sc.answer("join cp-2", resp, err)
		_, err = jc.JoinServer(sc.ctx, joinServerReq(t, tok.Token, "cp-3", "10.0.0.3"))
		sc.note("server token reused", err)
		// The join's own pass may promote the learner already; one more
		// makes sure.
		sc.sut.reconcile(sc.t)
		sc.eventually("the learner promoted", func() bool {
			ms, _ := sc.fc.Members(sc.ctx)
			return len(ms) == 2 && !ms[1].Learner
		})
		servers, err := sc.admin.ListServers(sc.ctx, &armadav1.ListServersRequest{})
		sc.answer("servers after promotion", servers, err)
		sc.keyspace("keyspace")

		// A failing AddLearner undoes the registration.
		sc.fc.mu.Lock()
		sc.fc.addErr = errors.New("etcd says no")
		sc.fc.mu.Unlock()
		tok2, err := sc.admin.CreateJoinToken(sc.ctx, &armadav1.CreateJoinTokenRequest{Server: true})
		if err != nil {
			t.Fatal(err)
		}
		id2, _, _ := strings.Cut(tok2.Token, ".")
		sc.alias(id2, "<server token 2>")
		_, err = jc.JoinServer(sc.ctx, joinServerReq(t, tok2.Token, "cp-4", "10.0.0.4"))
		sc.note("learner refused", err)
		sc.keyspace("keyspace after the refused learner")
	})
}

func TestParityNodes(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		for _, n := range []store.Node{{ID: "n1", PrivateIP: "10.0.0.11"}, {ID: "n2", PrivateIP: "10.0.0.12"}} {
			if err := sc.st.UpsertNode(sc.ctx, n); err != nil {
				t.Fatal(err)
			}
		}
		_, err := sc.admin.CordonNode(sc.ctx, &armadav1.CordonNodeRequest{Node: "n1", Cordoned: true})
		sc.note("cordon n1", err)
		_, err = sc.admin.CordonNode(sc.ctx, &armadav1.CordonNodeRequest{Node: "nope", Cordoned: true})
		sc.note("cordon nope", err)
		// A repeat within ten minutes folds into the event; later, a new one.
		_, err = sc.admin.CordonNode(sc.ctx, &armadav1.CordonNodeRequest{Node: "n1", Cordoned: true})
		sc.note("cordon n1 again", err)
		sc.advance(11 * time.Minute)
		_, err = sc.admin.CordonNode(sc.ctx, &armadav1.CordonNodeRequest{Node: "n1", Cordoned: true})
		sc.note("cordon n1 later", err)
		sc.note("cordoned events", sc.eventCount("n1", "Cordoned"))
		evs, err := sc.st.ListEvents(sc.ctx, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		var counts []int
		for _, e := range evs {
			if e.Reason == "Cordoned" {
				counts = append(counts, e.Count)
			}
		}
		sc.note("cordoned event counts", counts)
		for _, req := range []*armadav1.LabelNodeRequest{
			{Node: "n1"}, {Node: "n1", Set: map[string]string{"disk": "ssd", "zone": "a"}},
			{Node: "n1", Set: map[string]string{"armada.os": "x"}}, {Node: "n1", Set: map[string]string{"disk": "hdd"}, Remove: []string{"disk"}},
			{Node: "n1", Remove: []string{"zone"}}, {Node: "nope", Set: map[string]string{"a": "b"}},
		} {
			resp, err := sc.admin.LabelNode(sc.ctx, req)
			sc.answer("label", resp, err)
		}
		_, err = sc.admin.RestrictNode(sc.ctx, &armadav1.RestrictNodeRequest{Node: "n2", Restricted: true})
		sc.note("restrict n2", err)
		for _, req := range []*armadav1.SetNodeSiteRequest{{Node: "n2", Site: "far"}, {Node: "n2", Site: "Bad"}, {Node: "n2"}} {
			_, err := sc.admin.SetNodeSite(sc.ctx, req)
			sc.note("site "+req.Site, err)
		}
		for _, req := range []*armadav1.SetNodeRelayRequest{{Node: "n1"}, {Node: "../x"}, {Node: "n1", Clear: true}} {
			resp, err := sc.admin.SetNodeRelay(sc.ctx, req)
			sc.answer("relay "+req.Node, resp, err)
		}
		_, err = sc.admin.RotateNodeKey(sc.ctx, &armadav1.RotateNodeKeyRequest{Node: "n1"})
		sc.note("rotate a disconnected node's key", err)
		a, err := sc.connectAgent("n1", sc.nodeAgent("n1"), &armadav1.Hello{PrivateIp: "10.0.0.11", Version: "v1"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = sc.admin.RotateNodeKey(sc.ctx, &armadav1.RotateNodeKeyRequest{Node: "n1"})
		sc.note("rotate without the capability", err)
		_, err = sc.admin.RemoveNode(sc.ctx, &armadav1.RemoveNodeRequest{Node: "n1"})
		sc.note("remove n1", err)
		end := a.end()
		sc.note("n1's stream ends", end)
		sc.note("n1's last assignment", a.last)
		_, err = sc.admin.RemoveNode(sc.ctx, &armadav1.RemoveNodeRequest{Node: "n1"})
		sc.note("remove n1 again", err)
		sc.keyspace("keyspace")
	})
}

func TestParitySessions(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		if err := sc.st.UpsertNode(sc.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.11"}); err != nil {
			t.Fatal(err)
		}
		// A certificate of a node the cluster does not know.
		_, err := sc.connectAgent("ghost", sc.nodeAgent("ghost"), &armadav1.Hello{PrivateIp: "10.0.0.99"})
		sc.note("unregistered node", err)
		_, err = sc.connectAgent("n1", sc.nodeAgent("n1"), &armadav1.Hello{PrivateIp: "10.0.0.12"})
		sc.note("wrong private IP", err)
		_, err = sc.connectAgent("n1", sc.nodeAgent("n1"), nil)
		sc.note("no hello", err)
		// An unrecorded certificate of a known node.
		c, k := mustIssue(t, sc.fx.ca, pki.Identity{Kind: pki.KindNode, Name: "n1"})
		_, err = sc.connectAgent("n1", armadav1.NewAgentServiceClient(sc.dialPEM(c, k)), &armadav1.Hello{PrivateIp: "10.0.0.11"})
		sc.note("revoked certificate", err)

		hello := &armadav1.Hello{PrivateIp: "10.0.0.11", Version: "bad version!", Os: "linux", Arch: "amd64", CpuMillis: 1 << 40, MemoryBytes: -5,
			Jobs: true, Volumes: true, Containers: true, Nfs: true, NetworkKey: "short", Endpoint: "8.8.8.8", BehindNat: true}
		a, err := sc.connectAgent("n1", sc.nodeAgent("n1"), hello)
		if err != nil {
			t.Fatal(err)
		}
		sc.keyspace("connected")
		// A second connection replaces the first.
		b, err := sc.connectAgent("n1", sc.nodeAgent("n1"), &armadav1.Hello{PrivateIp: "10.0.0.11", Version: "v2"})
		if err != nil {
			t.Fatal(err)
		}
		sc.note("first stream ends", a.end())
		sc.keyspace("replaced")
		// The agent's own end.
		_ = b.stream.CloseSend()
		sc.note("second stream ends", errOf(b.end()))
		sc.eventually("disconnected", func() bool { return sc.eventCount("n1", "Disconnected") >= 1 })
		sc.keyspace("disconnected")
	})
}

const paritySpec = `name: web
image: registry.example.com/web:1
command: [/bin/web]
args: [--port, "8080"]
env:
  - name: PLAIN
    value: hello
  - name: DB
    secretRef: db-password
secretFiles:
  - secretRef: tls-key
    path: /etc/tls/key.pem
registry:
  server: registry.example.com
  username: bot
  passwordSecretRef: registry-password
ingress:
  type: internal
  port: 8080
probes:
  readiness:
    path: /ready
    period: 3s
    timeout: 1500ms
    failureThreshold: 4
  liveness:
    command: [/bin/check]
resources:
  cpu: 250m
  memory: 128Mi
initContainers:
  - name: migrate
    image: registry.example.com/migrate:1
    env:
      - name: DB
        secretRef: db-password
sidecars:
  - name: logs
    image: registry.example.com/logs:1
    args: [-v]
scale:
  min: 2
  max: 2
`

func TestParityAssignments(t *testing.T) {
	runParity(t, parityConfig{masterKey: true}, func(sc *scenario) {
		ctx := sc.ctx
		for _, n := range []store.Node{{ID: "n1", PrivateIP: "10.0.0.11"}, {ID: "n2", PrivateIP: "10.0.0.12"}} {
			if err := sc.st.UpsertNode(ctx, n); err != nil {
				t.Fatal(err)
			}
		}
		for _, kv := range [][2]string{{"db-password", "s3cret"}, {"tls-key", "-----KEY-----"}, {"registry-password", "pw"}} {
			key, val := kv[0], kv[1]
			seal := func(v int) (secrets.Sealed, error) {
				return sc.fx.keys.Seal("web", key, v, secrets.NewValue([]byte(val)))
			}
			if _, _, err := sc.st.SetSecret(ctx, "web", key, seal, false, "user:ryan"); err != nil {
				t.Fatal(err)
			}
		}
		sp, err := spec.Parse([]byte(paritySpec))
		if err != nil {
			t.Fatal(err)
		}
		rev, _, err := sc.st.Deploy(ctx, sp, "user:ryan")
		if err != nil {
			t.Fatal(err)
		}
		job, err := spec.Parse([]byte("kind: job\nname: batch\nimage: busybox\ncommand: [true]\ntasks: 3\nparallelism: 3\n"))
		if err != nil {
			t.Fatal(err)
		}
		jrev, _, err := sc.st.Deploy(ctx, job, "user:ryan")
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range []store.Replica{
			{ID: "web-r1-aaaaa", App: "web", Revision: rev.Name, NodeID: "n1"},
			{ID: "web-r1-bbbbb", App: "web", Revision: rev.Name, NodeID: "n2"},
			{ID: "web-r1-ccccc", App: "web", Revision: rev.Name, NodeID: "n1", Held: true},
			{ID: "batch-j1-t1-ddddd", App: "batch", Revision: jrev.Name, NodeID: "n2", Run: 1, Task: 1},
		} {
			if err := sc.st.CreateReplica(ctx, r); err != nil {
				t.Fatal(err)
			}
		}
		logs := map[string]any{"retentionSeconds": 86400, "maxBytes": 1 << 30}
		b, _ := json.Marshal(logs)
		if err := sc.st.SetMeta(ctx, "logs", string(b)); err != nil {
			t.Fatal(err)
		}
		n1, err := sc.connectAgent("n1", sc.nodeAgent("n1"), &armadav1.Hello{PrivateIp: "10.0.0.11", HeldReplicas: true})
		if err != nil {
			t.Fatal(err)
		}
		n2, err := sc.connectAgent("n2", sc.nodeAgent("n2"), &armadav1.Hello{PrivateIp: "10.0.0.12"})
		if err != nil {
			t.Fatal(err)
		}
		sc.sut.reconcile(sc.t)
		sc.note("n1", n1.assignment())
		sc.note("n2", n2.assignment())
		if got := n1.last.GetReplicas(); len(got) != 2 || got[0].GetEnv()[1].GetValue() != "s3cret" {
			t.Errorf("n1's replicas: %d", len(got))
		}

		// A report: states, readiness, digests, platforms; addresses not on
		// the node are dropped.
		n1.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Report{Report: &armadav1.ReplicaReport{Replicas: []*armadav1.ReplicaState{
			{Id: "web-r1-aaaaa", State: "running", Ready: true, ContainerId: "c1", Address: "10.0.0.11:31000",
				ImageDigest: "registry.example.com/web@sha256:" + strings.Repeat("a", 64), ImagePlatforms: []string{"linux/arm64", "linux/amd64"}},
			{Id: "web-r1-ccccc", State: "pulled", Address: "10.0.0.99:1", Message: "pulled\nimage"},
			{Id: "web-r1-bbbbb", State: "running"},
		}}}})
		sc.eventually("report applied", func() bool {
			r, err := sc.st.ListReplicas(ctx, store.ReplicaFilter{NodeID: "n1"})
			return err == nil && len(r) == 2 && slicesContainsState(r, "web-r1-aaaaa", "running") && slicesContainsState(r, "web-r1-ccccc", "pulled")
		})
		sc.eventually("digest recorded", func() bool {
			r, err := sc.st.GetRevision(ctx, rev.Name)
			return err == nil && r.ImageDigest != "" && len(r.Platforms) == 2
		})
		n2.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Report{Report: &armadav1.ReplicaReport{Replicas: []*armadav1.ReplicaState{
			{Id: "web-r1-bbbbb", State: "exited", ExitCode: 3, Message: "boom", ContainerId: "c2"},
			{Id: "batch-j1-t1-ddddd", State: "exited", Finished: true, ExitCode: 0, ContainerId: "c3"},
		}}}})
		sc.eventually("n2's report applied", func() bool { return sc.eventCount("web-r1-bbbbb", "Crashed") == 1 })
		sc.eventually("the job attempt finished", func() bool {
			r, err := sc.st.ListReplicas(ctx, store.ReplicaFilter{NodeID: "n2"})
			return err == nil && slicesContainsState(r, "batch-j1-t1-ddddd", "exited")
		})
		sc.sut.reconcile(sc.t)
		sc.note("n1 after the report", n1.assignment())
		// Usage: conditions on unreachable peers and a failing export.
		n2.send(&armadav1.AgentMessage{Msg: &armadav1.AgentMessage_Usage{Usage: &armadav1.UsageReport{PeersChecked: true,
			UnreachablePeers: []string{"n1", "Bad Name"}, WireguardUserspace: true,
			LogExport: &armadav1.LogExportStatus{Failing: true, Error: "503"}}}})
		sc.eventually("conditions", func() bool { return sc.eventCount("n2", "LogExportFailing") == 1 })
		sc.keyspace("keyspace")
	})
}

func slicesContainsState(rs []store.Replica, id, state string) bool {
	for _, r := range rs {
		if r.ID == id && r.State == state {
			return true
		}
	}
	return false
}

func TestParityRenewCertificate(t *testing.T) {
	runParity(t, parityConfig{nodeCertValidity: time.Hour}, func(sc *scenario) {
		if err := sc.st.UpsertNode(sc.ctx, store.Node{ID: "n1", PrivateIP: "10.0.0.11"}); err != nil {
			t.Fatal(err)
		}
		agent := sc.nodeAgent("n1")
		_, csr, err := pki.NewNodeCSR("n1")
		if err != nil {
			t.Fatal(err)
		}
		for _, req := range []*armadav1.RenewCertificateRequest{{}, {Csr: []byte("x")}, {Csr: csr}} {
			resp, err := agent.RenewCertificate(sc.ctx, req)
			sc.answer("renew", resp, err)
		}
		sc.keyspace("keyspace")
	})
}

func TestParityEventsAndStreamGuard(t *testing.T) {
	runParity(t, parityConfig{}, func(sc *scenario) {
		if _, err := sc.st.CreateSpace(sc.ctx, "b", "user:ryan", nil); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.st.CreateUser(sc.ctx, store.Principal{Name: "erin", Since: sc.clock.now().Add(-time.Hour)}, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		if _, err := sc.st.Assign(sc.ctx, store.KindUser, "erin", store.Grant{Role: store.RoleViewer, Space: "b"}, "user:ryan"); err != nil {
			t.Fatal(err)
		}
		for _, n := range []store.Node{{ID: "n1", PrivateIP: "10.0.0.11"}} {
			if err := sc.st.UpsertNode(sc.ctx, n); err != nil {
				t.Fatal(err)
			}
		}
		_, err := sc.admin.CordonNode(sc.ctx, &armadav1.CordonNodeRequest{Node: "n1", Cordoned: true})
		if err != nil {
			t.Fatal(err)
		}
		erin := sc.adminClient(pki.Identity{Kind: pki.KindUser, Name: "erin"})
		read := func(c armadav1.AdminServiceClient, req *armadav1.EventsRequest) ([]*armadav1.EventInfo, error) {
			s, err := c.Events(sc.ctx, req)
			if err != nil {
				return nil, err
			}
			var out []*armadav1.EventInfo
			for {
				e, err := s.Recv()
				if errors.Is(err, io.EOF) {
					return out, nil
				}
				if err != nil {
					return out, err
				}
				out = append(out, e)
			}
		}
		for _, c := range []struct {
			label string
			c     armadav1.AdminServiceClient
			req   *armadav1.EventsRequest
		}{
			{"admin", sc.admin, &armadav1.EventsRequest{}},
			{"admin, node", sc.admin, &armadav1.EventsRequest{Node: "n1"}},
			{"admin, since too far", sc.admin, &armadav1.EventsRequest{SinceSeconds: 90000}},
			{"erin", erin, &armadav1.EventsRequest{}},
			{"erin, node", erin, &armadav1.EventsRequest{Node: "n1"}},
			{"erin, another space's app", erin, &armadav1.EventsRequest{App: "web"}},
		} {
			evs, err := read(c.c, c.req)
			if err != nil {
				sc.note(c.label, err)
				continue
			}
			sc.note(c.label, evs)
		}
		// A follow ends once its principal is deleted.
		s, err := erin.Events(sc.ctx, &armadav1.EventsRequest{Follow: true, App: "web.b"})
		if err != nil {
			t.Fatal(err)
		}
		// The follow is open on the server (its headers wait for its first
		// event).
		time.Sleep(500 * time.Millisecond)
		if err := sc.st.DeletePrincipal(sc.ctx, store.KindUser, "erin", "user:ryan"); err != nil {
			t.Fatal(err)
		}
		_, err = s.Recv()
		sc.note("erin's follow", err)
	})
}

type etcdMemberInfo = etcd.MemberInfo

func credentialsJoin(ca *x509.Certificate) credentials.TransportCredentials {
	return credentials.NewTLS(pki.JoinClientTLS(ca))
}
