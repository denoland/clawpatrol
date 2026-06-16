package extplugin

import (
	"context"
	"fmt"
	"os"
	"strings"

	version "github.com/hashicorp/go-version"

	"github.com/denoland/clawpatrol/internal/config"
)

// This file backs the `clawpatrol plugins install|update|lock`
// subcommands: the operator-driven, network-touching half of the
// distribution flow. The running gateway never resolves or upgrades —
// it only loads the version these commands pin into the lockfile.

// InstalledPlugin reports the outcome of installing/updating one plugin.
type InstalledPlugin struct {
	Name      string
	Source    string
	Version   string
	Network   string
	Updated   bool   // version changed from what was previously locked
	WasLocked string // the previously-locked version ("" if new)
}

// Install downloads and caches each named GitHub-sourced plugin (all
// when names is empty), recording the resolved source/version, the
// declared network, and the binary hash in the lockfile. Local-path
// plugins are skipped (nothing to fetch). When upgrade is true it
// re-resolves to the newest release tag satisfying the constraint — the
// explicit upgrade; otherwise it keeps any already-pinned version and
// just ensures it is downloaded.
//
// Install probes each downloaded plugin's manifest (a throwaway
// network-denied spawn) to record its declared network, so it requires a
// working sandbox backend just like a normal load.
func (m *Manager) Install(ctx context.Context, specs []config.PluginSource, names []string, upgrade bool) ([]InstalledPlugin, error) {
	want := nameSet(names)
	if err := m.lock.load(); err != nil {
		return nil, err
	}
	f := newFetcher(m.stateDirLocked(), m.ghBase, m.prov, m.logger)

	var out []InstalledPlugin
	matched := map[string]bool{}
	for _, sp := range specs {
		if len(want) > 0 && !want[sp.Name] {
			continue
		}
		p, err := pluginSourceFor(sp)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", sp.Name, err)
		}
		matched[sp.Name] = true
		if !p.IsRemote() {
			continue // local path: nothing to install
		}

		entry, have := m.lock.get(sp.Name)
		prev := ""
		if have {
			prev = entry.Version
		}

		var r ghRelease
		if have && entry.Version != "" && !upgrade {
			// Keep the pinned version; just make sure it's downloaded.
			r, err = f.gh.releaseByTag(ctx, p.Owner, p.Repo, entry.Version)
		} else {
			r, _, err = f.gh.resolveVersion(ctx, p, sp.Version)
		}
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", sp.Name, err)
		}

		binPath, binSHA, err := f.ensure(ctx, p, r)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", sp.Name, err)
		}
		m.lock.setSource(sp.Name, p.slug(), r.TagName, strings.TrimSpace(sp.Version))

		network, err := m.declaredNetwork(ctx, sp, binPath)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", sp.Name, err)
		}
		m.lock.addHash(sp.Name, binSHA, network)

		out = append(out, InstalledPlugin{
			Name:      sp.Name,
			Source:    p.slug(),
			Version:   r.TagName,
			Network:   network,
			Updated:   prev != r.TagName,
			WasLocked: prev,
		})
	}
	if err := unknownNames(want, matched); err != nil {
		return nil, err
	}
	if err := m.lock.save(); err != nil {
		return nil, err
	}
	return out, nil
}

// LockPlatforms records, for each named GitHub-sourced plugin at its
// pinned version, the binary hash of every platform build the release
// ships — so one committed lockfile verifies the plugin on a mixed-OS
// team. It downloads and extracts each platform's archive to a temp dir
// (only the host platform's binary is cached) and adds every hash to the
// lockfile. A plugin must already be pinned (run `install` first).
func (m *Manager) LockPlatforms(ctx context.Context, specs []config.PluginSource, names []string) ([]InstalledPlugin, error) {
	want := nameSet(names)
	if err := m.lock.load(); err != nil {
		return nil, err
	}
	f := newFetcher(m.stateDirLocked(), m.ghBase, m.prov, m.logger)

	var out []InstalledPlugin
	matched := map[string]bool{}
	for _, sp := range specs {
		if len(want) > 0 && !want[sp.Name] {
			continue
		}
		p, err := pluginSourceFor(sp)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", sp.Name, err)
		}
		matched[sp.Name] = true
		if !p.IsRemote() {
			continue
		}
		entry, have := m.lock.get(sp.Name)
		if !have || entry.Version == "" {
			return nil, fmt.Errorf("plugin %q is not pinned; run `clawpatrol plugins install` first", sp.Name)
		}
		r, err := f.gh.releaseByTag(ctx, p.Owner, p.Repo, entry.Version)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", sp.Name, err)
		}
		plats, err := f.platformsInRelease(ctx, p, r)
		if err != nil {
			return nil, fmt.Errorf("plugin %q: %w", sp.Name, err)
		}
		tmp, err := os.MkdirTemp(m.stateDirLocked(), "lock-")
		if err != nil {
			return nil, err
		}
		for _, plat := range plats {
			_, binSHA, err := f.fetchTo(ctx, p, r, plat, tmp, "bin")
			if err != nil {
				_ = os.RemoveAll(tmp)
				return nil, fmt.Errorf("plugin %q (%s): %w", sp.Name, plat, err)
			}
			m.lock.addHash(sp.Name, binSHA, entry.Network)
		}
		_ = os.RemoveAll(tmp)
		out = append(out, InstalledPlugin{Name: sp.Name, Source: p.slug(), Version: entry.Version, Network: entry.Network})
	}
	if err := unknownNames(want, matched); err != nil {
		return nil, err
	}
	if err := m.lock.save(); err != nil {
		return nil, err
	}
	return out, nil
}

// CheckUpdates queries GitHub for each pinned GitHub-sourced plugin and
// records whether a newer release tag satisfying its constraint exists,
// so the dashboard can surface "update available". It never downloads or
// re-pins — applying an update is the operator's explicit `plugins
// update`. Per-plugin lookup errors are logged and skipped so one
// unreachable repo doesn't blank the whole set.
func (m *Manager) CheckUpdates(ctx context.Context, specs []config.PluginSource) {
	if err := m.lock.load(); err != nil {
		m.logger.Warn("plugin update check: read lockfile", "err", err)
		return
	}
	f := newFetcher(m.stateDirLocked(), m.ghBase, m.prov, m.logger)
	updates := map[string]string{}
	for _, sp := range specs {
		p, err := pluginSourceFor(sp)
		if err != nil || !p.IsRemote() {
			continue
		}
		entry, have := m.lock.get(sp.Name)
		if !have || entry.Version == "" {
			continue // not yet installed; nothing to compare against
		}
		r, newest, err := f.gh.resolveVersion(ctx, p, sp.Version)
		if err != nil {
			m.logger.Warn("plugin update check", "plugin", sp.Name, "err", err)
			continue
		}
		locked, err := version.NewVersion(entry.Version)
		if err != nil {
			continue
		}
		if newest.GreaterThan(locked) {
			updates[sp.Source] = r.TagName
		}
	}
	m.mu.Lock()
	m.updates = updates
	m.mu.Unlock()
	if len(updates) > 0 {
		m.logger.Info("plugin updates available", "count", len(updates))
	}
}

// declaredNetwork resolves the network grant to record at install time:
// an operator HCL override wins, else the plugin's manifest is probed.
func (m *Manager) declaredNetwork(ctx context.Context, sp config.PluginSource, binPath string) (string, error) {
	if sp.Network != "" {
		net, err := parseNetwork(sp.Network)
		return string(net), err
	}
	net, err := m.probeNetwork(ctx, sp, binPath)
	return string(net), err
}

func nameSet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	s := map[string]bool{}
	for _, n := range names {
		s[n] = true
	}
	return s
}

// unknownNames errors if the operator named a plugin that isn't in the
// config.
func unknownNames(want, matched map[string]bool) error {
	for n := range want {
		if !matched[n] {
			return fmt.Errorf("no plugin %q in config", n)
		}
	}
	return nil
}
