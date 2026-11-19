//go:build !windows

package gui

import "errors"

func relaunchElevated() error {
	return errors.New("restart pktreplay with sudo to get the privileges raw packet injection needs")
}
