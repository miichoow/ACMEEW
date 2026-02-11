"""Integration tests for the metrics collector."""

from acmeeh.metrics.collector import MetricsCollector


def test_collector_increment():
    """Counter should increment."""
    c = MetricsCollector()
    c.increment("test_counter")
    c.increment("test_counter")
    assert c.get("test_counter") == 2


def test_collector_labels():
    """Counters with different labels should be independent."""
    c = MetricsCollector()
    c.increment("http_requests", labels={"method": "GET", "status": "200"})
    c.increment("http_requests", labels={"method": "POST", "status": "201"})
    c.increment("http_requests", labels={"method": "GET", "status": "200"})

    assert c.get("http_requests", labels={"method": "GET", "status": "200"}) == 2
    assert c.get("http_requests", labels={"method": "POST", "status": "201"}) == 1


def test_collector_export():
    """Export should produce Prometheus-compatible text."""
    c = MetricsCollector()
    c.increment("test_total", labels={"method": "GET"})

    output = c.export()
    assert "acmeeh_uptime_seconds" in output
    assert "test_total" in output
    assert 'method="GET"' in output
