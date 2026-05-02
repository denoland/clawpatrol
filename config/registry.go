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
	byKey    map[regKey]*Plugin
	checkers []func(*Plugin) []string
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
	for _, check := range registry.checkers {
		if msgs := check(p); len(msgs) > 0 {
			panic(fmt.Sprintf("config.Register(%s/%s): %v", p.Kind, p.Type, msgs))
		}
	}
	registry.byKey[k] = p
}

// AddPluginChecker installs fn as a validator that runs at every
// future Register and retroactively against every already-registered
// plugin. Validators that return a non-empty []string panic the
// registration so plugin bugs surface at init time, not at first
// request.
//
// Used by config/runtime to enforce that Plugin.Runtime, when set,
// satisfies the expected interface for its Kind. Living as a callback
// here (rather than a config-package import of runtime) avoids a
// cycle: runtime already imports config; config doesn't depend on
// runtime.
func AddPluginChecker(fn func(*Plugin) []string) {
	registry.Lock()
	defer registry.Unlock()
	registry.checkers = append(registry.checkers, fn)
	// Retroactive: catch any plugin that registered before the
	// checker was installed.
	for _, p := range registry.byKey {
		if msgs := fn(p); len(msgs) > 0 {
			panic(fmt.Sprintf("AddPluginChecker(%s/%s): %v", p.Kind, p.Type, msgs))
		}
	}
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
