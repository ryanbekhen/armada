package cli

import "github.com/spf13/cobra"

// examples are the examples of commands that do not set their own
// (ADR 0052): two to four lines a person can copy, each with what it does.
// TestEveryCommandHasExamples checks every command has some, and that
// each one names a command and flags that exist.
var examples = map[string]string{ //nolint:gosec // command lines with placeholder names, no credentials
	"armada app list": `  armada app list            # the apps of the space
  armada app list -A         # of every space
  armada app list -o json`,
	"armada app show": `  armada app show api             # revision, replicas, URLs
  armada app show api -o yaml     # the spec it runs, for app deploy --file`,
	"armada app rollback": `  armada app rollback api              # to the revision before the active one
  armada app rollback api --to r11     # to one revision (armada revision list api)
  armada app rollback api --wait       # and wait until it serves`,
	"armada app logs": `  armada app logs api                     # the last 100 lines of each replica
  armada app logs api -f --grep error     # follow, only lines with "error"
  armada app logs api --since 2h          # search the history, replicas that are gone included
  armada app logs api --replica k3p9x --container log-ship`,
	"armada app top": `  armada app top              # every app of the space
  armada app top api          # one app, per replica
  armada app top --spaces     # per space, with volumes, requests, and egress`,
	"armada app events": `  armada app events              # what happened to the space's apps
  armada app events api -f       # one app, as it happens
  armada app events --since 2h`,
	"armada app delete": `  armada app delete api --yes   # drain its replicas, then delete it`,

	"armada revision list": `  armada revision list api`,
	"armada revision show": `  armada revision show api--r12          # image digest, platforms, secret versions
  armada revision show api--r12 -o json`,

	"armada job list": `  armada job list
  armada job list -o json`,
	"armada job show": `  armada job show migrate     # schedule, revision, latest run`,
	"armada job logs": `  armada job logs migrate               # the newest run
  armada job logs migrate --run 12      # one run (armada run list migrate)
  armada job logs migrate -f`,
	"armada job cancel": `  armada job cancel migrate   # stop its pending and running runs`,
	"armada job delete": `  armada job delete migrate`,

	"armada run list": `  armada run list migrate`,
	"armada run show": `  armada run show migrate 12   # one run, with its tasks`,

	"armada volume list": `  armada volume list           # every volume of the space
  armada volume list db        # one app's`,
	"armada volume backup": `  armada volume backup db data -o data.tar.gz          # while the app runs
  armada volume backup db data -o data.tar.gz --stop   # with the app paused, for a consistent copy`,
	"armada volume restore": `  armada volume restore db data data.tar.gz          # from an archive
  armada volume restore db data --snapshot latest    # from the volume's bucket
  armada volume restore db data --snapshot latest --node node2   # onto another node`,
	"armada volume delete": `  armada volume delete db data --yes`,

	"armada snapshot list":   `  armada snapshot list db data`,
	"armada snapshot create": `  armada snapshot create db data   # a backup to its bucket now`,

	"armada domain list": `  armada domain list               # every custom domain, with its TXT record
  armada domain list --app web`,
	"armada domain verify": `  armada domain verify www.example.com`,

	"armada cluster status": `  armada cluster status       # nodes, apps, and what needs attention
  armada cluster status -o json`,
	"armada cluster show": `  armada cluster show`,
	"armada cluster update": `  armada cluster update --root-domain apps.example.com
  armada cluster update --acme-email ops@example.com
  armada cluster update --trusted-proxies 173.245.48.0/20,103.21.244.0/22
  armada cluster update --log-retention 336h --log-max-disk 2Gi`,
	"armada cluster events": `  armada cluster events                   # the last day
  armada cluster events --node node1 -f   # one node, as it happens`,

	"armada node list": `  armada node list`,
	"armada node show": `  armada node show node1`,
	"armada node top":  `  armada node top     # CPU and memory used and reserved per node`,
	"armada node join-token": `  armada node join-token                       # prints the armadad join command
  armada node join-token --label disk=ssd      # the node joins with a label
  armada node join-token --ttl 30m`,
	"armada node drain":      `  armada node drain node1    # before maintenance; armada node resume node1 after`,
	"armada node resume":     `  armada node resume node1`,
	"armada node restrict":   `  armada node restrict node1   # only apps whose placement selects its labels`,
	"armada node unrestrict": `  armada node unrestrict node1`,
	"armada node delete": `  armada node delete node1           # moves its replicas away first
  armada node delete node1 --force   # a machine that is gone for good`,

	"armada server list": `  armada server list    # and update the client config with them`,
	"armada server join-token": `  armada server join-token          # prints the armadad server join command
  armada server join-token --ttl 30m`,
	"armada server delete": `  armada server delete server3`,

	"armada space list":   `  armada space list`,
	"armada space show":   `  armada space show shop`,
	"armada space create": `  armada space create shop`,
	"armada space use": `  armada space use shop      # later commands work in shop
  armada space use default`,
	"armada space update": `  armada space update default --network-isolation`,
	"armada space delete": `  armada space delete shop   # once its apps, jobs, and volumes are gone`,

	"armada user list": `  armada user list`,
	"armada user show": `  armada user show alice`,
	"armada user credentials": `  armada user credentials alice -o alice.config     # a new certificate; older ones stop working
  armada user credentials alice -o alice.config --ssh bastion.example.com`,
	"armada user update": `  armada user update alice --allow-label team=web
  armada user update alice --clear-labels`,
	"armada user delete": `  armada user delete alice --yes`,
	"armada user renew":  `  armada user renew    # before the certificate in your config expires`,

	"armada service list":        `  armada service list`,
	"armada service show":        `  armada service show ci`,
	"armada service credentials": `  armada service credentials ci -o ci.config   # another certificate; the others keep working`,
	"armada service update": `  armada service update ci --allow-label team=web
  armada service update ci --clear-labels`,
	"armada service delete": `  armada service delete ci --yes`,
	"armada service renew":  `  armada service renew --config ci.config`,

	"armada role list": `  armada role list    # the roles and who holds each`,
	"armada role show": `  armada role show deployer`,

	"armada alert list":   `  armada alert list`,
	"armada alert test":   `  armada alert test ops    # send a test notice now`,
	"armada alert delete": `  armada alert delete ops`,

	"armada metrics list": `  armada metrics list`,
	"armada metrics credentials": `  armada metrics credentials prometheus                    # ca.pem, cert.pem, key.pem in armada-metrics-prometheus
  armada metrics credentials prometheus -o /etc/prometheus/armada`,
	"armada metrics revoke": `  armada metrics revoke prometheus --yes`,

	"armada version": `  armada version             # this client, the servers, and the latest release
  armada version -o json`,
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
