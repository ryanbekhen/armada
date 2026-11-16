package containerd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/core/remotes/docker/config"

	"github.com/ryanbekhen/armada/internal/runtime"
)

// maxRegistryRedirects bounds the redirects one registry request follows.
const maxRegistryRedirects = 10

// errPlainRegistry refuses a registry request that is not HTTPS.
var errPlainRegistry = errors.New("registry requests must use https")

// newResolver returns the resolver an image pull uses. The agent pulls as
// root from the machine's network, at a registry the spec names, so the
// registry's answers must not steer it elsewhere: every request, the
// first, each redirect, and the token service's, is HTTPS (a redirect to
// plain HTTP is refused, and the server needs a certificate the machine
// trusts for the name it is reached by), no environment proxy is used,
// and no connection is made to a link-local (cloud metadata), unspecified,
// or multicast address, checked when dialling.
func newResolver(ctx context.Context, auth *runtime.RegistryAuth) remotes.Resolver {
	return docker.NewResolver(docker.ResolverOptions{
		Hosts: config.ConfigureHosts(ctx, config.HostOptions{
			// Always TLS, also for registries on localhost.
			DefaultScheme: "https",
			Credentials:   credentials(auth),
			UpdateClient:  guardRegistryClient,
		}),
	})
}

// guardRegistryClient applies newResolver's rules to a registry client;
// the token service shares it.
func guardRegistryClient(c *http.Client) error {
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("registry client: unexpected transport %T", c.Transport)
	}
	tr = tr.Clone()
	tr.Proxy = nil
	tr.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   registryDialControl,
	}).DialContext
	c.Transport = httpsOnly{tr}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRegistryRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRegistryRedirects)
		}
		if req.URL.Scheme != "https" {
			return errPlainRegistry
		}
		return nil
	}
	return nil
}

// httpsOnly refuses every request that is not HTTPS before it is sent.
type httpsOnly struct{ next http.RoundTripper }

func (t httpsOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, errPlainRegistry
	}
	return t.next.RoundTrip(req)
}

// registryDialControl refuses addresses no registry has, whatever name
// resolved to them.
func registryDialControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("registry address %q: %w", address, err)
	}
	if a := ap.Addr().Unmap(); !registryAddr(a) {
		return fmt.Errorf("registry address %s refused", a)
	}
	return nil
}

func registryAddr(a netip.Addr) bool {
	return !a.IsLinkLocalUnicast() && !a.IsMulticast() && !a.IsLinkLocalMulticast() &&
		!a.IsUnspecified() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}
