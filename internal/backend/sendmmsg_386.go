//go:build linux && 386

package backend

// The frozen syscall package omits sendmmsg on 386.
const sysSendmmsg = 345
