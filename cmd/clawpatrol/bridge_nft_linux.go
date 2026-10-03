//go:build linux

package main

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// The egress filter makes the pod fail closed even where the CNI leaves link
// or subnet routes in the main table: a packet may leave only through the
// tunnel, on loopback, as the bridge's own marked traffic, or as part of a
// connection that is already established (for example a reply to an inbound
// request). The filter does not reroute any packet. The table is the bridge's
// own, so it never changes other rules in the netns.
const bridgeNftTable = "clawpatrol"

// egressFilterRules returns the output chain rules in order. The chain policy
// is drop. In nft syntax:
//
//	oifname "lo" accept
//	oifname "<iface>" accept
//	meta mark <mark> accept
//	ct state established,related accept
//	icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
func egressFilterRules(iface string, mark uint32) [][]expr.Any {
	accept := &expr.Verdict{Kind: expr.VerdictAccept}
	oifname := func(name string) []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameData(name)},
			accept,
		}
	}
	icmpv6Type := func(typ byte) []expr.Any {
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{typ}},
			accept,
		}
	}
	return [][]expr.Any{
		oifname("lo"),
		oifname(iface),
		{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(mark)},
			accept,
		},
		{
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
			accept,
		},
		icmpv6Type(133), // router solicitation
		icmpv6Type(135), // neighbor solicitation
		icmpv6Type(136), // neighbor advertisement
	}
}

// ifnameData is an interface name as nftables compares it: NUL-padded to
// IFNAMSIZ.
func ifnameData(name string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return b
}

// applyEgressFilter replaces the bridge's table in one batch. Adding a table
// that exists is a no-op, so the delete in the same batch never fails.
func applyEgressFilter(c *nftables.Conn, iface string, mark uint32) error {
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: bridgeNftTable}
	c.AddTable(t)
	c.DelTable(t)
	c.AddTable(t)
	policy := nftables.ChainPolicyDrop
	ch := c.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})
	for _, exprs := range egressFilterRules(iface, mark) {
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: exprs})
	}
	return c.Flush()
}

func installEgressFilter(iface string, mark int) error {
	c, err := nftables.New()
	if err == nil {
		err = applyEgressFilter(c, iface, uint32(mark))
	}
	if err != nil {
		return fmt.Errorf("load the nftables egress filter (run with --egress-filter=off to start without it; see \"Runtime compatibility\" in the Kubernetes enrollment docs): %w", err)
	}
	return nil
}
