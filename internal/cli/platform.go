package cli

// Data and secrets directories of a node.
const (
	defaultDataDir    = "/var/lib/armada"
	defaultSecretsDir = "/run/armada/secrets" //nolint:gosec // a directory path, not a credential
)
