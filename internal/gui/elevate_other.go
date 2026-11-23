//go:build !windows

package gui

import "errors"

func relaunchElevated(string) error {
	return errors.New("restart pcapreplay with sudo to get the privileges raw packet injection needs")
}
