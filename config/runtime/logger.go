package runtime

import (
	"context"
	"time"
)

// LogLevel names a plugin diagnostic severity. Strings instead of an
// int enum so the dashboard can filter by query-param value directly
// and so JSON consumers don't need a translation table.
type LogLevel string

// Plugin diagnostic severities. Order matters for "min level"
// filtering: debug < info < warn < error.
const (
	LogDebug LogLevel = "debug"
	LogInfo  LogLevel = "info"
	LogWarn  LogLevel = "warn"
	LogError LogLevel = "error"
)

// Logger is the structured-diagnostic contract the gateway hands to
// plugins at request-handling time. Plugins call Log (or the package
// helpers Debug / Info / Warn / Error) instead of writing to stderr;
// the gateway buffers the events and surfaces them in the dashboard's
// /logs tab.
//
// Implementations must be safe for concurrent use — a single Logger
// is reused across goroutines (ConnEndpointRuntime spawns reader +
// writer pumps that both log against the same instance).
//
// Plugin authors do not implement Logger; they receive an instance
// from the host (via ConnHandle.Logger or LoggerFrom(ctx) for HTTP
// credential injection paths) and call its methods. fields must
// never carry credential bytes or other secret material — credential
// names/refs are fine.
type Logger interface {
	Log(level LogLevel, msg string, fields map[string]any)
}

// LogEntry is the on-wire shape of a buffered plugin diagnostic. The
// dashboard renders these directly; the SSE stream ships them as
// JSON. Plugins do not construct LogEntry values themselves — they
// invoke Logger methods and the gateway fills in Plugin / Ts.
type LogEntry struct {
	// Ts is when the gateway captured the event (UTC wall clock).
	Ts time.Time `json:"ts"`
	// Plugin is the registered plugin identifier — the (Kind, Type)
	// pair flattened as "credential/bearer_token",
	// "endpoint/postgres", etc. "gateway" for host-side log calls
	// that aren't attributable to a plugin.
	Plugin string `json:"plugin"`
	// Level is debug/info/warn/error.
	Level LogLevel `json:"level"`
	// Msg is the human-readable message body.
	Msg string `json:"msg"`
	// ReqID, when set, correlates the log entry to a request shown
	// on the live-requests page (UUIDv7 action_id). Empty for
	// session-scoped or startup-time events.
	ReqID string `json:"req_id,omitempty"`
	// AgentIP, when set, identifies the originating peer; the
	// dashboard uses it to scope the log tail to one device.
	AgentIP string `json:"agent_ip,omitempty"`
	// Fields carries arbitrary structured context. Plugins log
	// credential names/refs only — never secret bytes.
	Fields map[string]any `json:"fields,omitempty"`
}

// LevelAtLeast returns true when level is at or above min. Used by
// the dashboard's "min severity" filter on /api/logs.
func LevelAtLeast(level, min LogLevel) bool {
	return levelRank(level) >= levelRank(min)
}

func levelRank(l LogLevel) int {
	switch l {
	case LogDebug:
		return 0
	case LogInfo:
		return 1
	case LogWarn:
		return 2
	case LogError:
		return 3
	}
	// Unknown level — treat as info so callers don't silently drop
	// it under the typical default min=info filter.
	return 1
}

// loggerCtxKey is the context value used by LoggerFrom / WithLogger.
// Plugins that handle one request at a time (HTTPCredentialRuntime
// Inject*, HTTPSyntheticResponder RespondHTTP, ApproverRuntime
// Approve) read the per-request logger out of the context handed to
// them; the host installs the logger before dispatch.
type loggerCtxKey struct{}

// WithLogger returns a copy of ctx that carries lg. Host code calls
// this once per request before dispatching into plugin runtime hooks.
// Nil lg is a no-op (returns ctx unchanged) so callers don't need to
// branch.
func WithLogger(ctx context.Context, lg Logger) context.Context {
	if lg == nil {
		return ctx
	}
	return context.WithValue(ctx, loggerCtxKey{}, lg)
}

// LoggerFrom returns the plugin logger attached to ctx by WithLogger,
// or a no-op logger when none is set. Plugins always get a usable
// Logger — they never need to nil-check.
func LoggerFrom(ctx context.Context) Logger {
	if ctx == nil {
		return nopLogger{}
	}
	if lg, ok := ctx.Value(loggerCtxKey{}).(Logger); ok && lg != nil {
		return lg
	}
	return nopLogger{}
}

// Debug / Info / Warn / Error are convenience wrappers so plugin
// call sites read naturally:
//
//	runtime.Info(lg, "inject ok", map[string]any{"cred": name})
//
// rather than every caller spelling out lg.Log(runtime.LogInfo, ...).
// Nil-safe: a nil Logger discards.
func Debug(lg Logger, msg string, fields map[string]any) {
	if lg != nil {
		lg.Log(LogDebug, msg, fields)
	}
}

// Info records an informational diagnostic.
func Info(lg Logger, msg string, fields map[string]any) {
	if lg != nil {
		lg.Log(LogInfo, msg, fields)
	}
}

// Warn records a warning diagnostic.
func Warn(lg Logger, msg string, fields map[string]any) {
	if lg != nil {
		lg.Log(LogWarn, msg, fields)
	}
}

// Error records an error diagnostic.
func Error(lg Logger, msg string, fields map[string]any) {
	if lg != nil {
		lg.Log(LogError, msg, fields)
	}
}

type nopLogger struct{}

func (nopLogger) Log(LogLevel, string, map[string]any) {}

// NopLogger returns a Logger that discards every entry. Useful for
// tests that exercise plugin runtimes without standing up the
// gateway's log sink.
func NopLogger() Logger { return nopLogger{} }
