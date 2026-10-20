package speedcheck

import "github.com/prometheus/client_golang/prometheus"

type selectorMetrics struct {
	queries   *prometheus.CounterVec
	sources   *prometheus.CounterVec
	probes    *prometheus.CounterVec
	fallbacks *prometheus.CounterVec
	duration  prometheus.Histogram
	addresses prometheus.Histogram
	active    prometheus.Gauge
}

func newMetrics(tag string) selectorMetrics {
	labels := prometheus.Labels{"tag": tag}
	return selectorMetrics{
		queries:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "queries_total", Help: "Selections by result, without per-domain labels.", ConstLabels: labels}, []string{"result"}),
		sources:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "source_results_total", Help: "Complete DNS source results.", ConstLabels: labels}, []string{"source", "result"}),
		probes:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "probe_results_total", Help: "Probe subscriptions completed by outcome and cache status.", ConstLabels: labels}, []string{"outcome", "cached"}),
		fallbacks: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "fallback_total", Help: "Non-RTT selection outcomes by fixed reason (does not execute the outer fallback).", ConstLabels: labels}, []string{"reason"}),
		duration:  prometheus.NewHistogram(prometheus.HistogramOpts{Name: "selection_duration_seconds", Help: "End-to-end selector latency.", ConstLabels: labels, Buckets: prometheus.ExponentialBuckets(0.001, 2, 14)}),
		addresses: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "candidate_addresses", Help: "Unique admitted IPs per selection (capped at 64).", ConstLabels: labels, Buckets: []float64{0, 1, 2, 4, 8, 16, 32, 64}}),
		active:    prometheus.NewGauge(prometheus.GaugeOpts{Name: "inflight_queries", Help: "Active selector queries.", ConstLabels: labels}),
	}
}

func (s *Selector) RegisterMetricsTo(r prometheus.Registerer) error {
	collectors := []prometheus.Collector{s.metrics.queries, s.metrics.sources, s.metrics.probes, s.metrics.fallbacks, s.metrics.duration, s.metrics.addresses, s.metrics.active}
	for i, c := range collectors {
		if err := r.Register(c); err != nil {
			for _, old := range collectors[:i] {
				r.Unregister(old)
			}
			return err
		}
	}
	return nil
}
