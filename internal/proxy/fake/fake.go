// Package fake provides an in-memory proxy.Driver for tests.
package fake

import (
	"context"
	"sync"

	"github.com/ryanbekhen/armada/internal/proxy"
)

// Driver records applied configurations.
type Driver struct {
	mu      sync.Mutex
	applied []proxy.Config
	// Err, if set, is returned by Apply and Health.
	Err error
}

var _ proxy.Driver = (*Driver)(nil)

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
	return nil
}

// Health returns Err.
func (d *Driver) Health(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.Err
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
