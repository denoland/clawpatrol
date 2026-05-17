//go:build !linux

package main

import "net"

func originalDst(c net.Conn) (ip string, port uint16, ok bool)    { return "", 0, false }
func installExitNodeRedirect(listenPort int, extraPorts []string) {}
