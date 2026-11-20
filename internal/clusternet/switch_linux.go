//go:build linux

package clusternet

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
)

const (
	// probeEvery is how often the prepare step pings the peers again.
	probeEvery = 5 * time.Second
	// probeWait is how long a probe waits for the answers.
	probeWait = 2 * time.Second
	// maxUnreached bounds the peers a status names.
	maxUnreached = 32
)

// switchState is this node's side of a switch between modes (ADR 0050).
type switchState struct {
	to, step string
	// err is why the last pass failed, empty when it did not.
	err string
	// peers are the nodes to reach in the prepare step.
	peers []string
	// reached are the peers the last probe of this step heard from.
	reached map[string]bool
	probed  bool
	probing bool
	// moved is set once the move step's routes are in place.
	moved bool
}

// track records how a pass went for SwitchStatus and, in the prepare step,
// starts a probe of the target transport when one is due. n.mu is held.
func (n *Net) track(p plan, err error) {
	if !p.switching() {
		n.sw = switchState{}
		return
	}
	if n.sw.to != p.switchTo || n.sw.step != p.step {
		n.sw = switchState{to: p.switchTo, step: p.step}
	}
	n.sw.err = ""
	if err != nil {
		n.sw.err = err.Error()
	}
	n.sw.peers = n.sw.peers[:0]
	for _, pe := range p.peers {
		n.sw.peers = append(n.sw.peers, pe.node)
	}
	switch {
	case p.step == SwitchMove:
		n.sw.moved = err == nil
	case err == nil && !n.sw.probing:
		n.sw.probing = true
		// The probe runs in the caller's network namespace, which a
		// goroutine's thread is not bound to (tests run nodes in
		// namespaces of their own).
		ns, err := netns.Get()
		if err != nil {
			n.sw.probing = false
			n.sw.err = fmt.Sprintf("probe the target transport: %v", err)
			return
		}
		go n.probe(p, ns)
	}
}

// probe pings every peer's tunnel address over Next from the network
// namespace ns and records who answered through it, then waits before the
// next probe may start.
func (n *Net) probe(p plan, ns netns.NsHandle) {
	reached, err := inNamespace(ns, func() (map[string]bool, error) {
		return ping(vtepAddr(p.self.subnet), p.peers, probeWait)
	})
	if err != nil {
		n.log.Warn("probe the cluster network's target transport", "err", err)
	}
	n.mu.Lock()
	if n.sw.to == p.switchTo && n.sw.step == p.step {
		n.sw.reached, n.sw.probed = reached, true
	}
	n.mu.Unlock()
	time.Sleep(probeEvery - probeWait)
	n.mu.Lock()
	n.sw.probing = false
	n.mu.Unlock()
}

// inNamespace runs fn on a thread in the network namespace ns, and closes
// ns.
func inNamespace(ns netns.NsHandle, fn func() (map[string]bool, error)) (map[string]bool, error) {
	defer func() { _ = ns.Close() }()
	runtime.LockOSThread()
	cur, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	defer func() { _ = cur.Close() }()
	if !cur.Equal(ns) {
		if err := netns.Set(ns); err != nil {
			runtime.UnlockOSThread()
			return nil, err
		}
		// The thread stays locked and ends with the goroutine, so no
		// other goroutine runs in ns.
		return fn()
	}
	defer runtime.UnlockOSThread()
	return fn()
}

// SwitchStatus returns this node's side of a switch between modes for the
// agent's usage report, or nil while none runs.
func (n *Net) SwitchStatus() *armadav1.NetworkSwitchStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.sw.to == "" {
		return nil
	}
	st := &armadav1.NetworkSwitchStatus{To: n.sw.to, Step: n.sw.step, Error: n.sw.err}
	if n.sw.step == SwitchMove {
		st.Ready = n.sw.moved && n.sw.err == ""
		return st
	}
	var unreached []string
	for _, name := range n.sw.peers {
		if !n.sw.reached[name] {
			unreached = append(unreached, name)
		}
	}
	slices.Sort(unreached)
	st.Ready = n.sw.err == "" && n.sw.probed && len(unreached) == 0
	if len(unreached) > maxUnreached {
		unreached = unreached[:maxUnreached]
	}
	st.Unreached = unreached
	return st
}

// ping sends an ICMP echo request from self to every peer's tunnel address,
// which the prepare step routes over Next, and returns the peers whose reply
// came in through Next within wait.
func ping(self netip.Addr, peers []peer, wait time.Duration) (map[string]bool, error) {
	reached := map[string]bool{}
	if len(peers) == 0 {
		return reached, nil
	}
	next, err := net.InterfaceByName(Next)
	if err != nil {
		return reached, err
	}
	c, err := icmp.ListenPacket("ip4:icmp", self.String())
	if err != nil {
		return reached, fmt.Errorf("open an ICMP socket: %w", err)
	}
	defer func() { _ = c.Close() }()
	pc := c.IPv4PacketConn()
	if err := pc.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		return reached, err
	}
	id := (os.Getpid() ^ rand.IntN(1<<16)) & 0xffff //nolint:gosec // an echo identifier, not a secret
	byAddr := map[netip.Addr]string{}
	for i, pe := range peers {
		to := vtepAddr(pe.subnet)
		byAddr[to] = pe.node
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: i & 0xffff, Data: []byte("armada")}}
		b, err := msg.Marshal(nil)
		if err != nil {
			return reached, err
		}
		if _, err := c.WriteTo(b, &net.IPAddr{IP: to.AsSlice()}); err != nil {
			continue
		}
	}
	if err := c.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return reached, err
	}
	buf := make([]byte, 1500)
	for len(reached) < len(peers) {
		nb, cm, from, err := pc.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return reached, nil
			}
			return reached, err
		}
		if cm == nil || cm.IfIndex != next.Index {
			continue
		}
		m, err := icmp.ParseMessage(1, buf[:nb])
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		if e, ok := m.Body.(*icmp.Echo); !ok || e.ID != id {
			continue
		}
		ip, ok := from.(*net.IPAddr)
		if !ok {
			continue
		}
		if a, ok := netip.AddrFromSlice(ip.IP); ok {
			if name, ok := byAddr[a.Unmap()]; ok {
				reached[name] = true
			}
		}
	}
	return reached, nil
}
