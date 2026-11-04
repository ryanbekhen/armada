// Package embedded runs containers on Armada's own containerd instance
// (ADR 0011). Release builds carry containerd, runc, the CNI plugins,
// tini, and gVisor's runsc in the binary; this file pins exactly which
// upstream artifacts.
package embedded

import "strings"

// Artifact is one upstream download that contributes files to the bundle.
//
// When bumping a version: verify the upstream signature first (runc and
// tini publish GPG signatures; containerd and the CNI plugins publish
// checksums with the release; gVisor publishes SHA256SUMS with the GitHub
// release and a SHA-512 next to the same tarball in its own bucket, and
// both must agree), then record the SHA-256 here. The hash, not the URL,
// is what the bundle trusts.
type Artifact struct {
	Name    string
	Version string
	// URL has {arch} replaced by amd64 or arm64, or by Arch[arch] when
	// set (for projects that name architectures differently).
	URL    string
	Arch   map[string]string
	SHA256 map[string]string // by arch
	// Files maps a path inside the downloaded archive (a tar compressed
	// with gzip, or bzip2 when the URL ends in .tar.bz2) to its name in the
	// bundle. An empty map means the download is the file itself, named
	// Name.
	Files map[string]string
}

// Lock lists every artifact in the bundle.
var Lock = []Artifact{
	{
		Name:    "containerd",
		Version: "2.4.2",
		URL:     "https://github.com/containerd/containerd/releases/download/v2.4.2/containerd-static-2.4.2-linux-{arch}.tar.gz",
		SHA256: map[string]string{
			"amd64": "da656542e754c699a0f438eab925e6ffdbd6346a4428e659f83dc058f04dcffe",
			"arm64": "37b84b9534533672528141b9d815f58621a2fe5deee2daa84317800255756689",
		},
		Files: map[string]string{
			"bin/containerd":              "containerd",
			"bin/containerd-shim-runc-v2": "containerd-shim-runc-v2",
		},
	},
	{
		Name:    "runc",
		Version: "1.5.2",
		URL:     "https://github.com/opencontainers/runc/releases/download/v1.5.2/runc.{arch}",
		SHA256: map[string]string{
			"amd64": "599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488",
			"arm64": "d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0",
		},
	},
	{
		Name:    "cni-plugins",
		Version: "1.9.1",
		URL:     "https://github.com/containernetworking/plugins/releases/download/v1.9.1/cni-plugins-linux-{arch}-v1.9.1.tgz",
		SHA256: map[string]string{
			"amd64": "b98f74a0f8522f0a83867178729c1aa70f2158f90c45a2ca8fa791db1c76b303",
			"arm64": "56171987d3947707c3563db2f4001bccaf50fd63468611b9f3cbecb1375ee7ec",
		},
		Files: map[string]string{
			"./bridge":     "cni/bridge",
			"./host-local": "cni/host-local",
			"./loopback":   "cni/loopback",
			"./portmap":    "cni/portmap",
			"./firewall":   "cni/firewall",
		},
	},
	{
		Name:    "tini",
		Version: "0.19.0",
		URL:     "https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-{arch}",
		SHA256: map[string]string{
			"amd64": "c5b0666b4cb676901f90dfcb37106783c5fe2077b04590973b885950611b30ee",
			"arm64": "eae1d3aa50c48fb23b8cbdf4e369d0910dfc538566bfd09df89a774aa84a48b9",
		},
	},
	{
		// The userspace kernel of `isolation: sandbox` (ADR 0029). runsc
		// runs the sentry from gvisor-bin/ next to itself; the checkpoint
		// gofer and the metric server are left out (Armada uses neither).
		Name:    "gvisor",
		Version: "20261102.0",
		URL:     "https://github.com/google/gvisor/releases/download/release-20261102.0/gvisor-{arch}.tar.bz2",
		Arch:    map[string]string{"amd64": "x86_64", "arm64": "aarch64"},
		SHA256: map[string]string{
			"amd64": "6f6b1a8f0f4665a403238135167d0d990bfaeaff5544abf68f5e0d822b35484a",
			"arm64": "909c95f245a46000d3bb0d5285f07dde23597056e7c3a4aab758b218e95bdab0",
		},
		Files: map[string]string{
			"runsc":                              "runsc",
			"gvisor-bin/gvisor_sentry":           "gvisor-bin/gvisor_sentry",
			"gvisor-bin/gvisor-proc-umounter":    "gvisor-bin/gvisor-proc-umounter",
			"gvisor-bin/gvisor-sentry-prewarmer": "gvisor-bin/gvisor-sentry-prewarmer",
			"gvisor-bin/runsc-fd-parking":        "gvisor-bin/runsc-fd-parking",
		},
	},
}

// URLFor returns a's download URL for arch.
func (a Artifact) URLFor(arch string) string {
	name := arch
	if n, ok := a.Arch[arch]; ok {
		name = n
	}
	return strings.ReplaceAll(a.URL, "{arch}", name)
}

// Names of the bundled files the runtime uses.
const (
	BinContainerd = "containerd"
	BinShim       = "containerd-shim-runc-v2"
	BinRunc       = "runc"
	BinTini       = "tini"
	DirCNI        = "cni"
	// BinRunsc runs sandboxed containers (ADR 0029); it needs BinSentry
	// next to it.
	BinRunsc  = "runsc"
	BinSentry = "gvisor-bin/gvisor_sentry"
)
