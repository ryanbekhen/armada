package haproxy

import (
	"context"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// A sticky backend sets a cookie that names the slot, and every slot, empty
// ones too, answers to its own value (ADR 0036).
func TestRenderSticky(t *testing.T) {
	t.Parallel()
	cfg := proxy.Config{Backends: []proxy.Backend{
		{Name: "shop", Sticky: true, HealthPath: "/ready", Servers: []proxy.Server{{Name: "shop-1", Address: "10.0.0.2:80"}, {Name: "shop-2", Address: "10.0.0.3:80", Weight: 5}}},
		{Name: "api", Servers: []proxy.Server{{Name: "api-1", Address: "10.0.0.2:81"}}},
	}}
	out := ipRendered(cfg)
	shop := out[strings.Index(out, "backend be_shop\n"):]
	shop = shop[:strings.Index(shop, "\n\n")]
	name := stickyCookie("be_shop")
	if !strings.Contains(shop, "    cookie "+name+" insert indirect nocache httponly secure attr \"SameSite=Lax\"\n") {
		t.Errorf("no cookie:\n%s", shop)
	}
	for _, line := range strings.Split(shop, "\n") {
		if f := strings.Fields(line); len(f) > 1 && f[0] == "server" && !strings.HasSuffix(line, " cookie "+f[1]) {
			t.Errorf("server without its slot's cookie: %q", line)
		}
	}
	if strings.Contains(shop, "shop") && strings.Contains(name, "shop") {
		t.Error("the cookie name gives the app away")
	}
	if stickyCookie("be_shop") == stickyCookie("be_api") {
		t.Error("two backends share a cookie")
	}
	api := out[strings.Index(out, "backend be_api\n"):]
	if strings.Contains(api[:strings.Index(api, "\n\n")], "cookie") {
		t.Error("a backend that is not sticky sets a cookie")
	}
}

// Turning stickiness on or off reloads: it is in the backend's lines.
func TestStickyChangeReloads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	d, e, _, _ := newDriver(t)
	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", Servers: []proxy.Server{{Name: "web-1", Address: "10.0.0.2:80"}}}}}
	if err := d.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	e.running = true
	for _, sticky := range []bool{true, false} {
		before := e.reloads
		cfg.Backends[0].Sticky = sticky
		if err := d.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if e.reloads != before+1 {
			t.Errorf("sticky=%v: reloads = %d, want 1", sticky, e.reloads-before)
		}
	}
}
