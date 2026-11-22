package daemon

import "github.com/spf13/cobra"

// examples are armadad's examples (ADR 0052), by command path; the
// client's are in internal/cli. TestEveryCommandHasExamples checks them.
var examples = map[string]string{
	"armadad init": `  sudo armadad init                                  # a cluster on this machine, its first server
  sudo armadad init --network wireguard              # containers' traffic between nodes encrypted
  sudo armadad init --runtime embedded               # containers on containerd instead of the supervisor`,
	"armadad join": `  sudo armadad join 10.0.0.2:7444 --ca-hash sha256:3f1c...   # from armada node join-token; paste the token
  sudo armadad join 10.0.0.2:7444 --ca-hash sha256:3f1c... --token-file /root/token`,
	"armadad server": `  sudo systemctl enable --now armada-server   # how it normally runs, after init or server join
  sudo armadad server -v                      # in the foreground, with debug logs`,
	"armadad server join": `  sudo armadad server join 10.0.0.2:7444 --ca-hash sha256:3f1c...   # from armada server join-token
  sudo armadad server join 10.0.0.2:7444 --ca-hash sha256:3f1c... --name server2`,
	"armadad agent": `  sudo systemctl enable --now armada-agent    # how it normally runs, after join
  sudo armadad agent -v                       # in the foreground, with debug logs`,
	"armadad doctor": `  sudo armadad doctor                          # before init or join, and when something is off
  sudo armadad doctor --private-ip 10.0.0.5`,
	"armadad backup": `  sudo armadad backup -o cp-$(date +%F).tar     # the control plane, on a server
  sudo armadad backup list --backup-url url.txt --backup-key key.txt`,
	"armadad backup list": `  sudo armadad backup list --backup-url url.txt --backup-key key.txt`,
	"armadad restore": `  sudo armadad restore cp-2026-11-22.tar                               # from an archive
  sudo armadad restore --backup-url url.txt --backup-key key.txt         # the latest in the bucket
  sudo armadad restore --backup-url url.txt --backup-key key.txt --snapshot 20261122T030000.000Z-1a2b3c4d`,
	"armadad upgrade": `  sudo armadad upgrade                       # the latest release; servers first, one at a time
  sudo armadad upgrade --version v0.1.0-alpha.40
  sudo armadad upgrade --no-restart          # install only; restart the services later`,
	"armadad runtime": `  sudo systemctl status armada-runtime   # started by systemd on containerd nodes
  sudo armadad runtime reset             # remove every container Armada runs here`,
	"armadad runtime migrate": `  sudo armadad runtime migrate --to supervisor   # drain the node and stop its service first
  sudo armadad runtime migrate --to embedded`,
	"armadad runtime reset": `  sudo systemctl stop armada-agent && sudo armadad runtime reset`,
	"armadad endpoint show": `  sudo armadad endpoint show`,
	"armadad endpoint set": `  sudo armadad endpoint set 203.0.113.7    # the public address other sites reach this machine at
  sudo armadad endpoint set none           # behind NAT`,
	"armadad user renew": `  sudo armadad user renew    # an expired certificate in /etc/armada/admin.config`,
	"armadad version":    `  armadad version`,
}

// addExamples gives every command without examples its entry in examples.
func addExamples(root *cobra.Command) {
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if c.Example == "" {
			c.Example = examples[c.CommandPath()]
		}
	}
	walk(root)
}
