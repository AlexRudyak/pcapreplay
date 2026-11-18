//go:build linux && amd64

package backend

// The frozen syscall package omits sendmmsg on amd64.
const sysSendmmsg = 307
