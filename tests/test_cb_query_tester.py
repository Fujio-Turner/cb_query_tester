import sys
import types
import time
import unittest
from unittest import mock

# --- Stub external modules before importing the module under test ---
# Stub couchbase and its submodules to avoid requiring the real SDK
couchbase_mod = types.ModuleType("couchbase")
exceptions_mod = types.ModuleType("couchbase.exceptions")

class CouchbaseException(Exception):
    pass

class TimeoutException(Exception):
    pass

exceptions_mod.CouchbaseException = CouchbaseException
exceptions_mod.TimeoutException = TimeoutException

n1ql_mod = types.ModuleType("couchbase.n1ql")
class QueryProfile:
    PHASES = "PHASES"

n1ql_mod.QueryProfile = QueryProfile

options_mod = types.ModuleType("couchbase.options")
class ClusterOptions:
    def __init__(self, auth):
        self.auth = auth

class QueryOptions:
    def __init__(self, metrics=None, profile=None):
        self.metrics = metrics
        self.profile = profile

options_mod.ClusterOptions = ClusterOptions
options_mod.QueryOptions = QueryOptions

auth_mod = types.ModuleType("couchbase.auth")
class PasswordAuthenticator:
    def __init__(self, username, password):
        self.username = username
        self.password = password

auth_mod.PasswordAuthenticator = PasswordAuthenticator

cluster_mod = types.ModuleType("couchbase.cluster")
class Cluster:
    def __init__(self, *args, **kwargs):
        pass

    def ping(self):
        class DummyLatency:
            def total_seconds(self):
                return 0.001
        class DummyEndpoint:
            id = "id"
            local = "local"
            remote = "remote"
            state = "state"
            latency = DummyLatency()
        class DummyPing:
            id = "pid"
            sdk = "sdk"
            version = "ver"
            endpoints = {"query": [DummyEndpoint()]}
        return DummyPing()

    def close(self):
        pass

cluster_mod.Cluster = Cluster

# Stub numpy with a minimal argsort implementation
numpy_mod = types.ModuleType("numpy")
def argsort(seq):
    return list(sorted(range(len(seq)), key=lambda i: seq[i]))

numpy_mod.argsort = argsort

# Register stubs
sys.modules.setdefault("couchbase", couchbase_mod)
sys.modules.setdefault("couchbase.exceptions", exceptions_mod)
sys.modules.setdefault("couchbase.n1ql", n1ql_mod)
sys.modules.setdefault("couchbase.options", options_mod)
sys.modules.setdefault("couchbase.auth", auth_mod)
sys.modules.setdefault("couchbase.cluster", cluster_mod)
sys.modules.setdefault("numpy", numpy_mod)

# Now import the module under test
import cb_query_tester as mod


class TestParsePhaseTime(unittest.TestCase):
    def test_units_and_invalid(self):
        self.assertAlmostEqual(mod.parse_phase_time("100ns"), 0.0001, places=6)
        self.assertAlmostEqual(mod.parse_phase_time("250µs"), 0.25, places=6)
        self.assertEqual(mod.parse_phase_time("12.5ms"), 12.5)
        self.assertEqual(mod.parse_phase_time("2s"), 2000.0)
        self.assertEqual(mod.parse_phase_time("42"), 42.0)
        self.assertEqual(mod.parse_phase_time(None), 0.0)
        self.assertEqual(mod.parse_phase_time("abc"), 0.0)


class TestMeasureTime(unittest.TestCase):
    def test_decorator_measures_duration(self):
        @mod.measure_time
        def sample(x):
            time.sleep(0.01)
            return x * 2
        result, duration = sample(21)
        self.assertEqual(result, 42)
        self.assertGreaterEqual(duration, 0.009)


class TestGetExtremeQueries(unittest.TestCase):
    def test_extremes_timeline_and_chart(self):
        times = [10, 20, 30, 40, 50]
        profiles = [
            {"phaseTimes": {"phaseA": "1ms"}, "cpuTime": "2ms"}
            for _ in times
        ]
        ts = [0, 10, 20, 30, 40]  # seconds since epoch
        data = mod.get_extreme_queries(times, profiles, ts)

        # Fastest and slowest should be 1 each
        self.assertEqual(len(data["fastest_queries"]), 1)
        self.assertEqual(len(data["slowest_queries"]), 1)
        self.assertEqual(data["fastest_queries"][0]["iteration"], 1)
        self.assertEqual(data["slowest_queries"][0]["iteration"], 5)
        self.assertEqual(data["slowest_queries"][0]["execution_time_ms"], 50.0)
        # Profile times converted to floats
        self.assertEqual(data["fastest_queries"][0]["profile"]["phaseTimes"], {"phaseA": 1.0})
        self.assertEqual(data["fastest_queries"][0]["profile"]["cpuTime"], 2.0)

        # Timeline has flags
        tl = data["timeline"]
        self.assertEqual(len(tl), 5)
        self.assertTrue(tl[0]["fastest"])  # first is fastest
        self.assertTrue(tl[-1]["slowest"])  # last is slowest

        # Chart data groups by 30s buckets
        cd = data["chart_data"]
        self.assertEqual(len(cd), 2)
        # First bucket: times 10,20,30
        self.assertEqual(cd[0]["sum"], 3)
        self.assertEqual(cd[0]["min"], 10.0)
        self.assertEqual(cd[0]["max"], 30.0)
        self.assertEqual(cd[0]["mean"], 20.0)
        # Second bucket: times 40,50
        self.assertEqual(cd[1]["sum"], 2)
        self.assertEqual(cd[1]["min"], 40.0)
        self.assertEqual(cd[1]["max"], 50.0)
        self.assertEqual(cd[1]["mean"], 45.0)


class TestGenerateReport(unittest.TestCase):
    def test_basic_report(self):
        query_times = [10.0, 30.0, 20.0]
        conn_time = 0.123  # seconds
        query_metrics_list = [
            {"execution_time": 1.0, "elapsed_time": 1.2, "result_count": 10, "result_size": 100, "error_count": 0, "warning_count": 1},
            {"execution_time": 2.0, "elapsed_time": 2.2, "result_count": 20, "result_size": 200, "error_count": 1, "warning_count": 0},
            {"execution_time": 1.5, "elapsed_time": 2.0, "result_count": 15, "result_size": 150, "error_count": 0, "warning_count": 0},
        ]
        profiles_list = [
            {"phaseTimes": {"phaseX": "1ms"}},
            {"phaseTimes": {"phaseX": "2ms"}},
            {"phaseTimes": {"phaseX": "3ms"}},
        ]
        ping_summary = []
        latency_summary = {
            "kv": {"min": 1, "max": 3, "median": 2, "average": 2.0, "count": 3},
            "query": {"min": 0, "max": 0, "median": 0, "average": 0.0, "count": 0},
        }
        network_diagnostics = {}
        query_timestamps = [0, 10, 20]

        report = mod.generate_report(
            query_times,
            conn_time,
            query_metrics_list,
            profiles_list,
            ping_summary,
            latency_summary,
            network_diagnostics,
            query_timestamps,
            include_timeline=True,
        )

        self.assertIn("timing_statistics", report)
        self.assertAlmostEqual(report["timing_statistics"]["initial_connection_time_ms"], 123.0, places=2)
        self.assertEqual(report["timing_statistics"]["query_execution_times"]["min_ms"], 10.0)
        self.assertEqual(report["timing_statistics"]["query_execution_times"]["max_ms"], 30.0)
        self.assertEqual(report["timing_statistics"]["query_execution_times"]["median_ms"], 20.0)
        self.assertEqual(report["timing_statistics"]["query_execution_times"]["average_ms"], 20.0)

        qms = report["query_metrics_summary"]
        self.assertIn("execution_time", qms)
        # Note: code uses max(values) for non-time "average"; assert current behavior
        self.assertEqual(qms["result_count"]["average"], 20)

        qps = report["query_profile_summary"]
        self.assertEqual(qps["num_profiled_queries"], 3)
        self.assertIn("phaseX", qps["phase_stats"])  # aggregated phase present

        self.assertIn("query_timeline", report)
        self.assertEqual(len(report["onlineChartData"]), 1)


class TestPerformNetworkDiagnostics(unittest.TestCase):
    @mock.patch.object(mod, "run_verbose_ping", return_value="ping-out")
    @mock.patch.object(mod, "run_traceroute", return_value="traceroute-out")
    @mock.patch.object(mod, "test_tcp_connect", return_value=(True, 5.0, None))
    @mock.patch.object(mod, "resolve_dns_srv", return_value="No SRV records found.")
    @mock.patch("socket.gethostbyname_ex", return_value=("example.com", [], ["1.2.3.4"]))
    def test_no_srv_branch(self, *_):
        result = mod.perform_network_diagnostics("example.com")
        self.assertEqual(result["host"], "example.com")
        self.assertEqual(result["traceroute"], "traceroute-out")
        self.assertEqual(result["ping"], "ping-out")
        self.assertIn("ips", result)
        self.assertIn("tcp_tests", result)
        # Ensure common ports got entries
        self.assertTrue(any(k.endswith(":11207") for k in result["tcp_tests"].keys()))

    @mock.patch.object(mod, "run_verbose_ping", return_value="ping-out")
    @mock.patch.object(mod, "run_traceroute", return_value="traceroute-out")
    @mock.patch.object(mod, "test_tcp_connect", return_value=(True, 2.0, None))
    @mock.patch.object(mod, "resolve_dns_srv", return_value=[{"host": "node1", "port": 12345, "ips": ["1.2.3.4"]}])
    def test_srv_branch(self, *_):
        result = mod.perform_network_diagnostics("example.com")
        self.assertIn("tcp_tests", result)
        self.assertIsInstance(result["tcp_tests"], list)
        self.assertEqual(result["tcp_tests"][0]["host"], "node1")
        self.assertIn("tcp_tests", result["tcp_tests"][0])
        self.assertEqual(result["tcp_tests"][0]["tcp_tests"][0]["ip"], "1.2.3.4")
        self.assertTrue(result["tcp_tests"][0]["tcp_tests"][0]["success"])  # from stub


if __name__ == "__main__":
    unittest.main(verbosity=2)
