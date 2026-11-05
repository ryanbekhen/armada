package agent

import "syscall"

// noFollow keeps a restore from writing through a link.
const noFollow = syscall.O_NOFOLLOW
