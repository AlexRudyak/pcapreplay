//go:build !windows

package main

func consoleSoleOwner() bool { return false }

func holdWindow() {}
