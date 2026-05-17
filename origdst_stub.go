//go:build !linux

package main

import (
	"net"

	"github.com/denoland/clawpatrol/dnsvip"
)

func originalDst(c net.Conn) (ip string, port uint16, ok bool)    { return "", 0, false }
func installExitNodeRedirect(listenPort int, extraPorts []string) {}
func startUDPDNSListener(port int, dvip *dnsvip.Allocator)        {}
