// loaderhelper is a tiny dynamically-linked program the sandbox tests
// exec through the namespaces sandbox. It exists only to prove that
// the sandbox can run a binary whose dynamic loader lives outside the
// FHS /lib* dirs.
package main

import (
	"fmt"
	"net"
)

func main() {
	// net pulls the cgo resolver into the link, which links libc and
	// gives the binary a dynamic loader (.interp) — the condition the
	// loader binds address.
	if net.ParseIP("127.0.0.1") == nil {
		panic("unreachable")
	}
	fmt.Println("ok")
}
