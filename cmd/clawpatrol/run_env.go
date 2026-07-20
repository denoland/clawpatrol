package main

import (
	"flag"
	"strings"
	"sync"
)

// runEnvFlags controls the environment inherited by a wrapped command.
type runEnvFlags struct {
	inherit bool
	allow   stringListFlag
}

func (o *runEnvFlags) bind(fs *flag.FlagSet) {
	fs.BoolVar(&o.inherit, "inherit-env", false, "inherit the complete parent environment (may expose credentials)")
	fs.Var(&o.allow, "env", "inherit one environment variable by name (repeatable)")
}

type stringListFlag []string

func (f *stringListFlag) String() string { return strings.Join(*f, ",") }
func (f *stringListFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// pushedRunEnv records variables installed by env pushdown. Credential-looking
// parent values are replaced with these synthetic values instead of inherited.
var pushedRunEnv = struct {
	sync.Mutex
	values map[string]string
}{values: map[string]string{}}

func recordPushedRunEnv(name, value string) {
	pushedRunEnv.Lock()
	pushedRunEnv.values[name] = value
	pushedRunEnv.Unlock()
}

func sanitizedChildEnv(env []string, opts runEnvFlags) []string {
	if opts.inherit {
		return append([]string(nil), env...)
	}
	allowed := map[string]bool{}
	for _, name := range opts.allow {
		allowed[name] = true
	}
	out := make([]string, 0, len(env))
	pushedRunEnv.Lock()
	pushed := make(map[string]string, len(pushedRunEnv.values))
	for name, value := range pushedRunEnv.values {
		pushed[name] = value
	}
	pushedRunEnv.Unlock()
	for _, kv := range env {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if credentialEnvName(name) && !allowed[name] {
			if value, ok := pushed[name]; ok {
				out = append(out, name+"="+value)
				delete(pushed, name)
			}
			continue
		}
		out = append(out, kv)
		delete(pushed, name)
	}
	return out
}

func credentialEnvName(name string) bool {
	u := strings.ToUpper(name)
	if strings.HasPrefix(u, "CLAWPATROL_") {
		return false
	}
	for _, suffix := range []string{"_TOKEN", "_SECRET", "_KEY", "_PASSWORD", "_CREDENTIALS"} {
		if strings.HasSuffix(u, suffix) {
			return true
		}
	}
	return u == "AWS_ACCESS_KEY_ID" || u == "AWS_SESSION_TOKEN" || u == "GOOGLE_APPLICATION_CREDENTIALS"
}
