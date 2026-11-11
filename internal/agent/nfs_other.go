//go:build !linux

package agent

import (
	"context"
	"errors"
	"net/netip"
)

var netipParse = netip.ParseAddr

func nfsSupported() bool { return false }

func mountNFS(context.Context, string, string, string, bool) error {
	return errors.New("NFS volumes need Linux")
}

func unmountNFS(string) error { return nil }

func mountedSource(string) (string, bool, error) { return "", false, nil }

func mountedReadOnly(string) bool { return false }
