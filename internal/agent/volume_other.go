//go:build !unix

package agent

// noFollow: platforms without O_NOFOLLOW run no agent.
const noFollow = 0
