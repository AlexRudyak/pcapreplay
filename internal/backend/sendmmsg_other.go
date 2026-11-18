//go:build linux && !amd64 && !386

package backend

import "syscall"

const sysSendmmsg = syscall.SYS_SENDMMSG
