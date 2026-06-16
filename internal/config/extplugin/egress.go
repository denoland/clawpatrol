package extplugin

import (
	"net"
	"sort"
	"strings"

	pb "github.com/denoland/clawpatrol/internal/config/extplugin/proto"
)

// A plugin declares in its manifest the set of upstream targets it needs
// to reach via the gateway's brokered dial — "host:port" or
// "*.suffix.tld:port". The operator no longer has to know a plugin's
// destinations and hand-write them into every endpoint's `dial`: the
// manifest carries them, the gateway records the approved set in the
// lockfile (trust-on-first-use), and an upgrade that broadens the set —
// adds a destination none of the approved entries cover — fails closed
// until reapproved, exactly like the network-grant escalation check. The
// approved set is merged into each of the plugin's endpoint bindings'
// dial allow-list at dial time, so the same validateBrokeredDialTarget
// path enforces it. A plugin still runs network=none regardless; egress
// only bounds which targets the gateway opens on its behalf.

// egressFromManifest returns the plugin's declared brokered-dial egress
// targets, normalized.
func egressFromManifest(mf *pb.ManifestResponse) []string {
	return normalizeEgress(mf.GetCapabilities().GetEgress())
}

// normalizeEgress lowercases each entry's host, drops blanks and
// duplicates, and sorts the result so lockfile diffs and set comparisons
// are stable. Unparseable entries are kept verbatim (checkDialTarget
// reports them elsewhere) rather than silently dropped.
func normalizeEgress(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, e := range in {
		e = strings.TrimSpace(e)
		host, port, err := net.SplitHostPort(e)
		if err != nil {
			add(e)
			continue
		}
		add(net.JoinHostPort(strings.ToLower(host), port))
	}
	sort.Strings(out)
	return out
}

// hostCovers reports whether the approved-egress host pattern pat permits
// the declared host h. Each is an exact host or a "*.suffix" wildcard:
//
//   - exact covers only the identical host;
//   - "*.suffix" covers an exact host ending in ".suffix";
//   - "*.A" covers "*.B" iff B's suffix is within A's (a broader wildcard
//     covers a narrower one: "*.com" covers "*.foo.com", not vice versa).
//
// This mirrors validateBrokeredDialTarget's runtime wildcard semantics.
func hostCovers(pat, h string) bool {
	pat = strings.ToLower(pat)
	h = strings.ToLower(h)
	if pat == h {
		return true
	}
	patSuf, patWild := strings.CutPrefix(pat, "*")
	if !patWild {
		return false // exact pattern, non-identical host
	}
	if hSuf, hWild := strings.CutPrefix(h, "*"); hWild {
		// Both wildcards: "*.A" covers "*.B" iff ".B" ends with ".A".
		return strings.HasSuffix(hSuf, patSuf)
	}
	// Wildcard pattern vs exact host: "*.foo.com" covers "a.foo.com" but
	// not the bare "foo.com" (the leading dot must be present).
	return strings.HasSuffix(h, patSuf) && len(h) > len(patSuf)
}

// egressEntryCovers reports whether the approved entry pat permits the
// declared entry target. Ports must match exactly.
func egressEntryCovers(pat, target string) bool {
	ph, pp, err := net.SplitHostPort(pat)
	if err != nil {
		return false
	}
	th, tp, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	if pp != tp {
		return false
	}
	return hostCovers(ph, th)
}

// egressBroadened returns the declared egress entries that no approved
// entry covers — the destinations an upgrade newly wants to reach. Empty
// means the declared set is within (equal to or narrower than) approved.
func egressBroadened(approved, declared []string) []string {
	var broadened []string
	for _, d := range declared {
		covered := false
		for _, a := range approved {
			if egressEntryCovers(a, d) {
				covered = true
				break
			}
		}
		if !covered {
			broadened = append(broadened, d)
		}
	}
	return broadened
}
