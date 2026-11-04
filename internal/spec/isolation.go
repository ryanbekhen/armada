package spec

import "fmt"

// Kernel isolation levels of a project (ADR 0029): how its containers are
// kept from the node's kernel.
const (
	// IsolationContainer runs containers on the node's kernel, confined by
	// namespaces, cgroups, seccomp, and SELinux where enforcing.
	IsolationContainer = "container"
	// IsolationSandbox runs each replica in a userspace kernel (gVisor), so
	// its system calls never reach the node's kernel directly.
	IsolationSandbox = "sandbox"
	// IsolationVM runs each replica in its own virtual machine; not built
	// yet.
	IsolationVM = "vm"
)

// DefaultIsolation is the level of a new project other than default.
const DefaultIsolation = IsolationSandbox

// IsolationRank orders the levels from weakest (0) to strongest; -1 for
// anything else. An empty level is container, the level of everything
// stored before levels existed.
func IsolationRank(level string) int {
	switch level {
	case "", IsolationContainer:
		return 0
	case IsolationSandbox:
		return 1
	case IsolationVM:
		return 2
	}
	return -1
}

// CheckIsolation returns an error unless level can be set on a project
// today.
func CheckIsolation(level string) error {
	switch level {
	case IsolationContainer, IsolationSandbox:
		return nil
	case IsolationVM:
		return fmt.Errorf("isolation vm is not supported yet; use container or sandbox")
	}
	return fmt.Errorf("unknown isolation %q: use container or sandbox", level)
}
