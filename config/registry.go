package config

import (
	"fmt"
	"sort"
	"sync"
)

// registry holds every plugin registered at init time. The blank-
// import chain rooted at config/plugins/all/all.go pulls in every
// built-in plugin's package so its init() runs before main().
var registry struct {
	sync.RWMutex
	byKey map[regKey]*Plugin
}

type regKey struct {
	Kind Kind
	Type string
}

// Register installs a plugin. Called from each plugin package's
// init(). Duplicate (Kind, Type) pairs panic — they always indicate
// a build-time mistake.
func Register(p *Plugin) {
	if p == nil {
		panic("config.Register: nil plugin")
	}
	if p.Kind == "" {
		panic("config.Register: plugin Kind is empty")
	}
	if p.New == nil {
		panic(fmt.Sprintf("config.Register(%s/%s): New is nil", p.Kind, p.Type))
	}
	if p.Build == nil {
		panic(fmt.Sprintf("config.Register(%s/%s): Build is nil", p.Kind, p.Type))
	}
	if p.Kind.LabelCount() == 2 && p.Type == "" {
		panic(fmt.Sprintf("config.Register(%s): Type is required for two-label kinds", p.Kind))
	}
	registry.Lock()
	defer registry.Unlock()
	if registry.byKey == nil {
		registry.byKey = make(map[regKey]*Plugin)
	}
	k := regKey{Kind: p.Kind, Type: p.Type}
	if _, dup := registry.byKey[k]; dup {
		panic(fmt.Sprintf("config.Register: duplicate plugin %s/%s", p.Kind, p.Type))
	}
	registry.byKey[k] = p
}

// Lookup returns the plugin for (kind, type), or nil if none is
// registered. The loader uses this to dispatch block decoding.
func Lookup(kind Kind, typ string) *Plugin {
	registry.RLock()
	defer registry.RUnlock()
	return registry.byKey[regKey{Kind: kind, Type: typ}]
}

// Types returns every registered Type for the given kind, sorted.
// Used to render "unknown <kind> type \"X\" — known types: ..." hints.
func Types(kind Kind) []string {
	registry.RLock()
	defer registry.RUnlock()
	var out []string
	for k := range registry.byKey {
		if k.Kind == kind {
			out = append(out, k.Type)
		}
	}
	sort.Strings(out)
	return out
}
