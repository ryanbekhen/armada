package daemon

import (
	"crypto/x509"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ryanbekhen/armada/internal/clientconfig"
	"github.com/ryanbekhen/armada/internal/pki"
)

// adminWarnBefore is how long before a user certificate expires
// doctor starts warning: it is the one certificate renewed by hand.
const adminWarnBefore = 30 * 24 * time.Hour

// checkCertificates checks the certificates on this machine: the ones
// Armada renews itself (server, etcd member, node) must not be past their
// renewal point by much, and the user certificate in the client
// config must not be close to expiring.
func checkCertificates(env doctorEnv) []checkResult {
	now := env.now()
	var problems []checkResult
	var good []string
	next := time.Time{}
	note := func(c *x509.Certificate) {
		if next.IsZero() || c.NotAfter.Before(next) {
			next = c.NotAfter
		}
	}
	day := func(t time.Time) string { return t.UTC().Format(time.DateOnly) }

	auto := []struct{ file, what, fix string }{
		{fileServerCert, "server", "restart armada-server: it renews its certificates at start"},
		{filepath.Join(dirEtcd, "member.crt"), "etcd member", "restart armada-server: it renews its certificates at start"},
		{fileNodeCert, "node", "remove the node with `armada node delete` and join it again"},
	}
	if _, err := env.readFile(filepath.Join(env.dataDir, fileServerCert)); err == nil {
		auto[2].fix = "restart armada-server: on a server it renews this node's certificate at start"
	}
	for _, a := range auto {
		b, err := env.readFile(filepath.Join(env.dataDir, a.file))
		if err != nil {
			continue
		}
		c, err := pki.ParseCertPEM(b)
		if err != nil {
			problems = append(problems, checkResult{"certificates", checkFail, fmt.Sprintf("%s certificate %s: %v", a.what, a.file, err)})
			continue
		}
		life := c.NotAfter.Sub(c.NotBefore)
		switch left := c.NotAfter.Sub(now); {
		case left <= 0:
			problems = append(problems, checkResult{"certificates", checkFail, fmt.Sprintf("%s certificate expired on %s; %s", a.what, day(c.NotAfter), a.fix)})
		case left < life/6:
			problems = append(problems, checkResult{"certificates", checkWarn, fmt.Sprintf("%s certificate expires on %s and was not renewed; check the logs (journalctl -u armada-server -u armada-agent)", a.what, day(c.NotAfter))})
		default:
			good = append(good, a.what)
			note(c)
		}
	}

	if cc, err := clientconfig.Load(env.adminConfig); err == nil {
		if c, err := pki.ParseCertPEM([]byte(cc.Cert)); err == nil {
			if id, err := pki.IdentityFromCert(c); err == nil && (id.Kind == pki.KindUser || id.Kind == pki.KindAdmin) {
				switch left := c.NotAfter.Sub(now); {
				case left <= 0:
					problems = append(problems, checkResult{"certificates", checkFail, fmt.Sprintf("user certificate in %s expired on %s; on a server, renew it with `armadad user renew --data-dir %s`", env.adminConfig, day(c.NotAfter), env.dataDir)})
				case left < adminWarnBefore:
					problems = append(problems, checkResult{"certificates", checkWarn, fmt.Sprintf("user certificate in %s expires on %s; renew it with `armada rbac user renew`", env.adminConfig, day(c.NotAfter))})
				default:
					good = append(good, "user")
					note(c)
				}
			}
		}
	}

	if len(good) > 0 {
		problems = append(problems, checkResult{"certificates", checkOK, fmt.Sprintf("%s valid; the first expires on %s", strings.Join(good, ", "), day(next))})
	}
	return problems
}
