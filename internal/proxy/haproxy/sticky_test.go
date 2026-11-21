package haproxy

import (
	"context"
	"strings"
	"testing"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// A sticky backend sets a cookie, and each server answers to a value that
// names its replica without giving it away (ADR 0036); empty slots to none.
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
	want := map[string]string{"10.0.0.2:80": stickyValue("shop-1"), "10.0.0.3:80": stickyValue("shop-2")}
	for _, line := range strings.Split(shop, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "server" {
			continue
		}
		if v, ok := want[f[2]]; ok {
			if !strings.Contains(line+" ", " cookie "+v+" ") {
				t.Errorf("server without its replica's cookie %s: %q", v, line)
			}
			delete(want, f[2])
		} else if strings.Contains(line, " cookie ") {
			t.Errorf("an empty slot has a cookie: %q", line)
		}
	}
	if len(want) != 0 {
		t.Errorf("servers missing: %v", want)
	}
	if v := stickyValue("shop-1"); strings.Contains(v, "shop") || v == stickyValue("shop-2") {
		t.Errorf("cookie value %q gives the replica away or is shared", v)
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

// Every node sends a client with a cookie to the same replica, whatever slot
// the replica has in its proxy: the value follows the replica.
func TestStickyCookieSameOnEveryNode(t *testing.T) {
	t.Parallel()
	cfg := proxy.Config{Backends: []proxy.Backend{{Name: "shop", Sticky: true, Servers: []proxy.Server{
		{Name: "shop-1", Address: "10.0.0.2:80"}, {Name: "shop-2", Address: "10.0.0.3:80"}, {Name: "shop-3", Address: "10.0.0.4:80"},
	}}}}
	cookies := func(layout Layout) map[string]string {
		out := map[string]string{}
		for _, line := range strings.Split(string(render(cfg, layout, renderOptions{})), "\n") {
			f := strings.Fields(line)
			if len(f) >= 5 && f[0] == "server" && f[3] == "cookie" {
				out[f[2]] = f[4]
			}
		}
		return out
	}
	one := cookies(Layout{"be_shop": {"shop-1", "shop-2", "shop-3", "", "", "", "", "", "", ""}})
	two := cookies(Layout{"be_shop": {"shop-3", "", "shop-1", "shop-2", "", "", "", "", "", ""}})
	if len(one) != 3 || len(two) != 3 {
		t.Fatalf("cookies: %v / %v", one, two)
	}
	for addr, v := range one {
		if two[addr] != v {
			t.Errorf("%s: cookie %s on one node, %s on another", addr, v, two[addr])
		}
	}
}

// A sticky server's cookie is set by a load, so a slot taking another
// replica reloads; an address change of the same replica does not, and
// backends that are not sticky never reload for their replicas.
func TestStickyReplicaChangeReloads(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, sticky := range []bool{true, false} {
		d, e, _, _ := newDriver(t)
		cfg := proxy.Config{Backends: []proxy.Backend{{Name: "web", Sticky: sticky, Servers: []proxy.Server{{Name: "web-1", Address: "10.0.0.2:80"}}}}}
		if err := d.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		e.running = true
		before := e.reloads
		cfg.Backends[0].Servers = []proxy.Server{{Name: "web-1", Address: "10.0.0.9:80"}}
		if err := d.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if e.reloads != before {
			t.Errorf("sticky=%v: an address change reloaded", sticky)
		}
		cfg.Backends[0].Servers = []proxy.Server{{Name: "web-1", Address: "10.0.0.9:80"}, {Name: "web-2", Address: "10.0.0.3:80"}}
		if err := d.Apply(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if got, want := e.reloads-before, map[bool]int{true: 1, false: 0}[sticky]; got != want {
			t.Errorf("sticky=%v: a new replica reloaded %d times, want %d", sticky, got, want)
		}
	}
}

func TestSameStructureSeesStickyCookies(t *testing.T) {
	t.Parallel()
	a := []byte("backend be_web\n    server s1 10.0.0.2:80 cookie raaaa inter 15s\n    server s2 127.0.0.1:1 disabled\n")
	if !sameStructure(a, []byte("backend be_web\n    server s1 10.0.0.7:80 weight 3 cookie raaaa\n    server s2 10.0.0.8:80\n")) {
		t.Error("addresses and weights made a different structure")
	}
	if sameStructure(a, []byte("backend be_web\n    server s1 10.0.0.2:80 cookie rbbbb inter 15s\n    server s2 127.0.0.1:1 disabled\n")) {
		t.Error("another cookie looked like the same structure")
	}
}
