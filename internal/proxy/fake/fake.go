// Package fake provides an in-memory proxy.Driver for tests.
package fake

import (
	"context"
	"errors"
	"sync"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// Driver records applied configurations.
type Driver struct {
	mu      sync.Mutex
	applied []proxy.Config
	// Err, if set, is returned by Apply and Health.
	Err error
	// down makes Health fail until the next successful Apply, like a
	// proxy that stopped and is started again.
	down bool
	load map[string]proxy.ServerLoad
}

var (
	_ proxy.Driver     = (*Driver)(nil)
	_ proxy.LoadReader = (*Driver)(nil)
)

// SetLoad sets the requests in progress Load reports, keeping totals.
func (d *Driver) SetLoad(load map[string]int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	next := map[string]proxy.ServerLoad{}
	for k, v := range load {
		next[k] = proxy.ServerLoad{InFlight: v, Total: d.load[k].Total}
	}
	d.load = next
}

// AddRequests counts n more requests to server name.
func (d *Driver) AddRequests(name string, n int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.load == nil {
		d.load = map[string]proxy.ServerLoad{}
	}
	l := d.load[name]
	l.Total += n
	d.load[name] = l
}

// Load returns what SetLoad and AddRequests set, or Err.
func (d *Driver) Load(context.Context) (map[string]proxy.ServerLoad, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Err != nil {
		return nil, d.Err
	}
	out := make(map[string]proxy.ServerLoad, len(d.load))
	for k, v := range d.load {
		out[k] = v
	}
	return out, nil
}

// Apply validates and records cfg, like a real driver would.
func (d *Driver) Apply(_ context.Context, cfg proxy.Config) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Err != nil {
		return d.Err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	d.applied = append(d.applied, cfg)
	d.down = false
	return nil
}

// Health returns Err, or an error while the proxy is down.
func (d *Driver) Health(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Err == nil && d.down {
		return errors.New("proxy is not running")
	}
	return d.Err
}

// Stop makes the proxy unhealthy until the next Apply.
func (d *Driver) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.down = true
}

// SetErr changes Err safely.
func (d *Driver) SetErr(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Err = err
}

// Applied returns how many configs were applied and the latest one.
func (d *Driver) Applied() (int, proxy.Config) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.applied) == 0 {
		return 0, proxy.Config{}
	}
	return len(d.applied), d.applied[len(d.applied)-1]
}

// History returns every applied config, oldest first.
func (d *Driver) History() []proxy.Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]proxy.Config(nil), d.applied...)
}
