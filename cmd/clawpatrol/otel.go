// OpenTelemetry bootstrap. Opt-in via OTEL_EXPORTER_OTLP_ENDPOINT.
// When unset, no SDK init, no goroutines, no allocations beyond
// reading env strings.

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	gometrics "runtime"
	"time"

	otelruntime "go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Module-globals so main.go's hooks can call cheap helpers without
// threading a metrics handle through every call site. Nil until
// StartOtel runs; helpers below no-op until then.
var (
	mConns       metric.Int64UpDownCounter
	mVerdicts    metric.Int64Counter
	mReqDuration metric.Float64Histogram
)

// genaiTracer is the tracer used to emit OTel GenAI semantic-convention
// spans for intercepted LLM turns. Set by StartOtel when the trace
// exporter is configured; nil otherwise, in which case recordGenAITurn
// no-ops. Threading a tracer through every call site would be noisier
// than this module-global, matching the metric handles above.
var genaiTracer trace.Tracer

func StartOtel(g *Gateway) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	otlpEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if otlpEndpoint == "" {
		return noop, nil
	}

	// Default error handler swallows export failures silently — without
	// this, "no metrics in backend" is undebuggable.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		log.Printf("otel: %v", err)
	}))

	otlpExp, err := otlpmetrichttp.New(context.Background())
	if err != nil {
		return noop, fmt.Errorf("otlp metric exporter: %w", err)
	}
	interval := 60 * time.Second
	if v := os.Getenv("OTEL_METRIC_EXPORT_INTERVAL"); v != "" {
		if d, perr := time.ParseDuration(v + "ms"); perr == nil {
			interval = d
		}
	}

	// resource.Default() reads OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES.
	// Setting attrs in code would win over env via Merge's later-wins rule,
	// locking operators out of changing identity without a rebuild.
	res := resource.Default()

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(otlpExp,
			sdkmetric.WithInterval(interval),
		)),
	)
	otel.SetMeterProvider(provider)

	if err := otelruntime.Start(otelruntime.WithMinimumReadMemStatsInterval(15 * time.Second)); err != nil {
		log.Printf("otel: runtime instrumentation: %v", err)
	}

	if err := registerClawpatrolGauges(provider.Meter("clawpatrol"), g); err != nil {
		return noop, fmt.Errorf("register gauges: %w", err)
	}

	var tpShutdown = noop
	texp, err := otlptracehttp.New(context.Background())
	if err != nil {
		log.Printf("otel: otlp trace exporter: %v (continuing without traces)", err)
	} else {
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			sdktrace.WithBatcher(texp),
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
		)
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{},
		))
		genaiTracer = tp.Tracer("clawpatrol")
		tpShutdown = tp.Shutdown
		_, span := tp.Tracer("clawpatrol").Start(context.Background(), "gateway.boot")
		span.SetAttributes(attribute.String("event", "startup"))
		span.End()
		// Force-flush so the boot span hits the backend immediately
		// instead of waiting on BatchSpanProcessor's 5s timer.
		go func() {
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := tp.ForceFlush(flushCtx); err != nil {
				log.Printf("otel: trace force-flush: %v", err)
			}
		}()
		// Heartbeat so service discovery doesn't time out between restarts.
		go func() {
			t := time.NewTicker(60 * time.Second)
			defer t.Stop()
			tracer := tp.Tracer("clawpatrol")
			for range t.C {
				_, sp := tracer.Start(context.Background(), "gateway.heartbeat")
				sp.End()
			}
		}()
	}

	log.Printf("otel: otlp/http push enabled → %s (interval=%s)", otlpEndpoint, interval)
	return func(ctx context.Context) error {
		_ = tpShutdown(ctx)
		return provider.Shutdown(ctx)
	}, nil
}

func registerClawpatrolGauges(meter metric.Meter, g *Gateway) error {
	if _, err := meter.Int64ObservableGauge("clawpatrol.hitl.pending",
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			if g.hitl == nil {
				return nil
			}
			g.hitl.mu.Lock()
			n := len(g.hitl.pending)
			g.hitl.mu.Unlock()
			o.Observe(int64(n))
			return nil
		}),
	); err != nil {
		return fmt.Errorf("otel gauge clawpatrol.hitl.pending: %w", err)
	}

	if _, err := meter.Int64ObservableGauge("clawpatrol.sse.subscribers",
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			if g.sink == nil {
				return nil
			}
			g.sink.mu.Lock()
			n := len(g.sink.subs)
			g.sink.mu.Unlock()
			o.Observe(int64(n))
			return nil
		}),
	); err != nil {
		return fmt.Errorf("otel gauge clawpatrol.sse.subscribers: %w", err)
	}

	if _, err := meter.Int64ObservableCounter("clawpatrol.sse.drops",
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			if g.sink == nil {
				return nil
			}
			o.Observe(int64(g.sink.Drops()))
			return nil
		}),
	); err != nil {
		return fmt.Errorf("otel counter clawpatrol.sse.drops: %w", err)
	}

	if _, err := meter.Int64ObservableGauge("clawpatrol.agents.count",
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			if g.agents == nil {
				return nil
			}
			g.agents.mu.RLock()
			n := len(g.agents.agents)
			g.agents.mu.RUnlock()
			o.Observe(int64(n))
			return nil
		}),
	); err != nil {
		return fmt.Errorf("otel gauge clawpatrol.agents.count: %w", err)
	}

	if _, err := meter.Int64ObservableGauge("clawpatrol.agents.sessions",
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			if g.agents == nil {
				return nil
			}
			g.agents.mu.RLock()
			var n int
			for _, a := range g.agents.agents {
				n += len(a.Sessions)
			}
			g.agents.mu.RUnlock()
			o.Observe(int64(n))
			return nil
		}),
	); err != nil {
		return fmt.Errorf("otel gauge clawpatrol.agents.sessions: %w", err)
	}

	if _, err := meter.Int64ObservableCounter("clawpatrol.agents.requests",
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			if g.agents == nil {
				return nil
			}
			g.agents.mu.RLock()
			var n int64
			for _, a := range g.agents.agents {
				n += a.Reqs
			}
			g.agents.mu.RUnlock()
			o.Observe(n)
			return nil
		}),
	); err != nil {
		return fmt.Errorf("otel counter clawpatrol.agents.requests: %w", err)
	}

	if _, err := meter.Int64ObservableGauge("clawpatrol.agents.bytes_total",
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			if g.agents == nil {
				return nil
			}
			g.agents.mu.RLock()
			var in, out int64
			for _, a := range g.agents.agents {
				in += a.BytesIn
				out += a.BytesOut
			}
			g.agents.mu.RUnlock()
			o.Observe(in, metric.WithAttributes(attribute.String("dir", "in")))
			o.Observe(out, metric.WithAttributes(attribute.String("dir", "out")))
			return nil
		}),
	); err != nil {
		return fmt.Errorf("otel gauge clawpatrol.agents.bytes_total: %w", err)
	}

	{
		var err error
		if mConns, err = meter.Int64UpDownCounter("clawpatrol.connections.open"); err != nil {
			return fmt.Errorf("otel up-down clawpatrol.connections.open: %w", err)
		}
		if mVerdicts, err = meter.Int64Counter("clawpatrol.verdicts"); err != nil {
			return fmt.Errorf("otel counter clawpatrol.verdicts: %w", err)
		}
		if mReqDuration, err = meter.Float64Histogram("clawpatrol.request.duration",
			metric.WithUnit("s"),
		); err != nil {
			return fmt.Errorf("otel histogram clawpatrol.request.duration: %w", err)
		}
	}

	// contrib/instrumentation/runtime omits go.memory.type=heap
	// (only stack and other), so we source heap from runtime.MemStats.
	if _, err := meter.Int64ObservableGauge("clawpatrol.process.memory.heap_inuse",
		metric.WithUnit("By"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			var ms gometrics.MemStats
			gometrics.ReadMemStats(&ms)
			o.Observe(int64(ms.HeapInuse))
			return nil
		}),
	); err != nil {
		return fmt.Errorf("otel gauge clawpatrol.process.memory.heap_inuse: %w", err)
	}

	return nil
}

func otelTrackConn(mode string) func() {
	if mConns == nil {
		return func() {}
	}
	attrs := metric.WithAttributes(attribute.String("mode", mode))
	mConns.Add(context.Background(), 1, attrs)
	return func() { mConns.Add(context.Background(), -1, attrs) }
}

func otelRecordVerdict(verdict string) {
	if mVerdicts == nil {
		return
	}
	mVerdicts.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("verdict", verdict),
	))
}

func otelRecordRequest(d time.Duration, verdict string, status int) {
	if mReqDuration == nil {
		return
	}
	klass := ""
	switch {
	case status >= 500:
		klass = "5xx"
	case status >= 400:
		klass = "4xx"
	case status >= 300:
		klass = "3xx"
	case status >= 200:
		klass = "2xx"
	}
	mReqDuration.Record(context.Background(), d.Seconds(), metric.WithAttributes(
		attribute.String("verdict", verdict),
		attribute.String("status_class", klass),
	))
}
