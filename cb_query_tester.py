import time
import logging
import argparse
import os
import json
import subprocess
import socket
import signal
import sys
from urllib.parse import urlparse
from statistics import mean, median
from datetime import datetime, timedelta, timezone
import math
import numpy as np
from couchbase.cluster import Cluster
from couchbase.options import ClusterOptions, QueryOptions
from couchbase.n1ql import QueryProfile
from couchbase.auth import PasswordAuthenticator
from couchbase.exceptions import CouchbaseException, TimeoutException

__version__ = "0.1.0"

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logging.warning("dnspython not installed; DNS SRV resolution will be skipped. Install with 'pip install dnspython' for full diagnostics.")

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command-line arguments for Couchbase connection details and options."""
    parser = argparse.ArgumentParser(description="Couchbase Capella query performance test")
    parser.add_argument(
        "-u", "--username",
        required=True,
        help="Couchbase Capella username"
    )
    parser.add_argument(
        "-p", "--password",
        required=True,
        help="Couchbase Capella password"
    )
    parser.add_argument(
        "-U", "--url",
        required=True,
        help="Couchbase Capella cluster URL (e.g., couchbases://cb.<cluster-id>.cloud.couchbase.com)"
    )
    parser.add_argument(
        "-b", "--bucket",
        required=True,
        help="Bucket name to query (e.g., travel-sample)"
    )
    parser.add_argument(
        "-n", "--num-iterations",
        type=int,
        default=10,
        help="Number of query iterations (default: 10)"
    )
    parser.add_argument(
        "-q", "--query",
        default=None,
        help="Custom N1QL query to execute (overrides default)"
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output the final report as JSON instead of logging"
    )
    parser.add_argument(
        "-r", "--report-only",
        action="store_true",
        help="Output only the final report (JSON or text) to stdout, suppressing other logs"
    )
    parser.add_argument(
        "-s", "--skip",
        action="store_true",
        help="Skip network diagnostics (DNS, traceroute, ping) and proceed to query execution"
    )
    parser.add_argument(
        "-t", "--timeline",
        action="store_true",
        help="Include a query timeline with timestamps and execution times in the report"
    )
    return parser.parse_args()

def configure_logging(report_only):
    """Configure logging based on report-only flag."""
    if report_only:
        logging.getLogger().handlers = []
        logging.getLogger().setLevel(logging.CRITICAL + 1)

def run_traceroute(host):
    """Run traceroute to the host and return output with longer timeout."""
    try:
        result = subprocess.run(['traceroute', '-n', '-w', '5', host], capture_output=True, text=True, timeout=60)
        return result.stdout if result.returncode == 0 else f"Traceroute failed: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Traceroute timed out after 60 seconds."
    except Exception as e:
        return f"Traceroute execution failed: {str(e)}"

def run_verbose_ping(host):
    """Run verbose ping to the host and return output with longer timeout."""
    try:
        result = subprocess.run(['ping', '-c', '3', '-W', '5', host], capture_output=True, text=True, timeout=30)
        return result.stdout if result.returncode == 0 else f"Ping failed: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Ping timed out after 30 seconds."
    except Exception as e:
        return f"Ping execution failed: {str(e)}"

def resolve_dns_srv(host):
    """Resolve DNS SRV records for Couchbase TLS."""
    if not DNS_AVAILABLE:
        return "dnspython not available; skipping SRV resolution."
    try:
        srv_query = '_couchbases._tls.' + host
        answers = dns.resolver.resolve(srv_query, 'SRV')
        nodes = []
        for answer in answers:
            node_host = str(answer.target).rstrip('.')
            port = answer.port
            try:
                ips = socket.gethostbyname_ex(node_host)[2]
            except Exception as e:
                ips = f"DNS resolution failed: {str(e)}"
            nodes.append({
                'host': node_host,
                'port': port,
                'ips': ips
            })
        return nodes
    except dns.resolver.NoAnswer:
        return "No SRV records found."
    except Exception as e:
        return f"SRV resolution failed: {str(e)}"

def test_tcp_connect(host, port, timeout=10):
    """Test TCP connection to host:port and measure time."""
    start_time = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            end_time = time.time()
            return True, round((end_time - start_time) * 1000, 2)
    except Exception as e:
        end_time = time.time()
        return False, round((end_time - start_time) * 1000, 2), str(e)

def perform_network_diagnostics(host):
    """Perform enhanced network diagnostics mimicking SDK Doctor with Capella TLS ports."""
    diagnostics = {
        'host': host,
        'traceroute': run_traceroute(host),
        'ping': run_verbose_ping(host),
        'srv_records': resolve_dns_srv(host)
    }
    
    if isinstance(diagnostics['srv_records'], list) and len(diagnostics['srv_records']) > 0:
        for node in diagnostics['srv_records']:
            if isinstance(node['ips'], list):
                node['tcp_tests'] = []
                for ip in node['ips']:
                    success, latency, error = test_tcp_connect(ip, node['port'])
                    node['tcp_tests'].append({
                        'ip': ip,
                        'success': success,
                        'latency_ms': latency,
                        'error': error if not success else None
                    })
            else:
                node['tcp_tests'] = [{'error': node['ips']}]
        diagnostics['tcp_tests'] = diagnostics['srv_records']
    else:
        common_ports = [11207, 18091, 18093, 18094, 18097]
        try:
            ips = socket.gethostbyname_ex(host)[2]
            diagnostics['ips'] = ips
            diagnostics['tcp_tests'] = {}
            for port in common_ports:
                success, latency, error = test_tcp_connect(host, port)
                diagnostics['tcp_tests'][f"{host}:{port}"] = {
                    'success': success,
                    'latency_ms': latency,
                    'error': error if not success else None
                }
        except Exception as e:
            diagnostics['ips'] = f"DNS resolution failed: {str(e)}"
            diagnostics['tcp_tests'] = {}
    
    return diagnostics

def measure_time(func):
    """Decorator to measure execution time of a function."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        return result, end_time - start_time
    return wrapper

@measure_time
def connect_to_cluster(connection_url, username, password):
    """Establish connection to Couchbase cluster."""
    try:
        logger.debug("Initiating connection to Couchbase Capella at %s", connection_url)
        auth = PasswordAuthenticator(username, password)
        cluster = Cluster(connection_url, ClusterOptions(auth))
        logger.debug("Connection object created, performing ping to verify connectivity")
        ping_result = cluster.ping()
        logger.debug("Cluster ping result: %s", ping_result)
        if ping_result:
            for service, endpoints in ping_result.endpoints.items():
                for endpoint in endpoints:
                    logger.info(
                        "%s service ping: %.2f ms to %s",
                        service, (endpoint.latency.total_seconds() * 1000), endpoint.remote
                    )
        return cluster, ping_result
    except TimeoutException as e:
        logger.error("Connection to cluster timed out: %s", e)
        raise
    except CouchbaseException as e:
        logger.error("Failed to connect to cluster: %s", e)
        raise
    except Exception as e:
        logger.error("Unexpected error during cluster connection: %s", e)
        raise

@measure_time
def execute_query(cluster, query, bucket_name):
    """Execute the N1QL query and return timing information."""
    try:
        logger.debug("Executing query: %s", query)
        options = QueryOptions(metrics=True, profile=QueryProfile.PHASES)
        result = cluster.query(query, options)
        rows = list(result)
        logger.debug("Query executed, retrieved %d rows", len(rows))
        
        metrics = result.metadata().metrics()
        query_metrics = {}
        if metrics:
            query_metrics = {
                'execution_time': metrics.execution_time().total_seconds() * 1000 if metrics.execution_time() else 0,
                'elapsed_time': metrics.elapsed_time().total_seconds() * 1000 if metrics.elapsed_time() else 0,
                'result_count': int(metrics.result_count().value) if metrics.result_count() else len(rows),
                'result_size': int(metrics.result_size().value) if metrics.result_size() else 0,
                'error_count': int(metrics.error_count().value) if metrics.error_count() else 0,
                'warning_count': int(metrics.warning_count().value) if metrics.warning_count() else 0
            }
        else:
            logger.warning("No metrics returned for query on bucket %s.", bucket_name)
            query_metrics = {
                'execution_time': 0,
                'elapsed_time': 0,
                'result_count': len(rows),
                'result_size': 0,
                'error_count': 0,
                'warning_count': 0
            }
        logger.debug("Query metrics: %s", query_metrics)
        
        profile = result.metadata().profile()
        if profile:
            logger.info("Query execution plan (profile): %s", profile)
            if 'phaseTimes' in profile:
                logger.info("Phase times: %s", profile['phaseTimes'])
        else:
            logger.warning("No profile information returned for query on %s", bucket_name)
        
        return query_metrics, profile
    except CouchbaseException as e:
        logger.error("Query execution failed for bucket %s: %s", bucket_name, e)
        raise

def summarize_ping_metrics(ping_results):
    """Summarize ping latencies and details across all iterations."""
    ping_summary = []
    service_latencies = {
        'kv': [],
        'query': [],
        'search': [],
        'views': [],
        'mgmt': []
    }
    
    for i, ping_result in enumerate(ping_results, 1):
        if ping_result:
            ping_info = {
                'iteration': i,
                'id': ping_result.id,
                'sdk': ping_result.sdk,
                'version': ping_result.version,
                'endpoints': {}
            }
            for service, endpoints in ping_result.endpoints.items():
                for endpoint in endpoints:
                    latency_ms = endpoint.latency.total_seconds() * 1000
                    if service in service_latencies:
                        service_latencies[str(service)] = service_latencies.get(str(service), [])
                        service_latencies[str(service)].append(latency_ms)
                    ping_info['endpoints'][str(service)] = {
                        'id': endpoint.id,
                        'local': endpoint.local,
                        'remote': endpoint.remote,
                        'latency_ms': latency_ms,
                        'state': str(endpoint.state)
                    }
            ping_summary.append(ping_info)
    
    latency_summary = {}
    for service, latencies in service_latencies.items():
        if latencies:
            latency_summary[service] = {
                'min': min(latencies),
                'max': max(latencies),
                'median': median(latencies),
                'average': mean(latencies),
                'count': len(latencies)
            }
        else:
            latency_summary[service] = {
                'min': 0,
                'max': 0,
                'median': 0,
                'average': 0,
                'count': 0
            }
    
    return ping_summary, latency_summary

def parse_phase_time(time_str):
    """Parse phase time string to milliseconds."""
    if time_str is None:
        return 0.0
    time_str = time_str.strip()
    if time_str.endswith('ns'):
        return float(time_str[:-2]) / 1e6
    elif time_str.endswith('µs'):
        return float(time_str[:-2]) / 1000
    elif time_str.endswith('ms'):
        return float(time_str[:-2])
    elif time_str.endswith('s'):
        return float(time_str[:-1]) * 1000
    else:
        try:
            return float(time_str)
        except ValueError:
            return 0.0

def get_extreme_queries(query_times, profiles_list, query_timestamps):
    """Identify top 1% slowest and bottom 1% fastest queries with their plans."""
    if not query_times or not profiles_list:
        return {'slowest_queries': [], 'fastest_queries': [], 'timeline': [], 'chart_data': []}
    
    num_queries = min(len(query_times), len(profiles_list), len(query_timestamps))
    query_times = query_times[:num_queries]
    profiles_list = profiles_list[:num_queries]
    query_timestamps = query_timestamps[:num_queries]
    
    num_extreme = max(1, int(num_queries * 0.01))
    sorted_indices = np.argsort(query_times)
    
    fastest_indices = set(sorted_indices[:num_extreme])
    slowest_indices = set(sorted_indices[-num_extreme:][::-1])
    
    fastest_queries = []
    for idx in sorted_indices[:num_extreme]:
        if profiles_list[idx]:
            profile = profiles_list[idx].copy()
            if 'phaseTimes' in profile:
                profile['phaseTimes'] = {k: float(round(parse_phase_time(v), 6)) for k, v in profile['phaseTimes'].items()}
            if 'cpuTime' in profile:
                profile['cpuTime'] = float(round(parse_phase_time(profile['cpuTime']), 6))
            fastest_queries.append({
                'iteration': int(idx + 1),
                'execution_time_ms': float(round(query_times[idx], 2)),
                'profile': profile
            })
    
    slowest_queries = []
    for idx in sorted_indices[-num_extreme:][::-1]:
        if profiles_list[idx]:
            profile = profiles_list[idx].copy()
            if 'phaseTimes' in profile:
                profile['phaseTimes'] = {k: float(round(parse_phase_time(v), 6)) for k, v in profile['phaseTimes'].items()}
            if 'cpuTime' in profile:
                profile['cpuTime'] = float(round(parse_phase_time(profile['cpuTime']), 6))
            slowest_queries.append({
                'iteration': int(idx + 1),
                'execution_time_ms': float(round(query_times[idx], 2)),
                'profile': profile
            })
    
    # Create timeline
    timeline = []
    if query_timestamps:
        timeline = [
            {
                'dt': datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                'v': float(round(query_times[i], 2)),
                'slowest': i in slowest_indices,
                'fastest': i in fastest_indices
            } for i, ts in enumerate(query_timestamps)
        ]
    
    # Create chart data grouped by 30-second intervals
    chart_data = []
    if query_timestamps:
        # Group by 30-second intervals
        time_groups = {}
        for i, ts in enumerate(query_timestamps):
            # Floor timestamp to nearest 30 seconds
            ts_floored = math.floor(ts / 30) * 30
            if ts_floored not in time_groups:
                time_groups[ts_floored] = []
            time_groups[ts_floored].append(query_times[i])
        
        # Calculate sum, min, max, mean for each group
        for ts_floored in sorted(time_groups.keys()):
            times = time_groups[ts_floored]
            chart_data.append({
                'dt': datetime.fromtimestamp(ts_floored, timezone.utc).isoformat(),
                'sum': len(times),
                'min': float(round(min(times), 2)),
                'max': float(round(max(times), 2)),
                'mean': float(round(mean(times), 2))
            })
    
    return {
        'slowest_queries': slowest_queries,
        'fastest_queries': fastest_queries,
        'timeline': timeline,
        'chart_data': chart_data
    }

def generate_report(query_times, conn_time, query_metrics_list, profiles_list, ping_summary, latency_summary, network_diagnostics, query_timestamps, include_timeline, tool_version: str | None = None):
    """Generate the report structure for logging or JSON."""
    report = {
        'tool_version': tool_version or __version__,
        'onlineChartData': get_extreme_queries(query_times, profiles_list, query_timestamps)['chart_data'],
        'timing_statistics': {
            'initial_connection_time_ms': float(round(conn_time * 1000, 2)) if conn_time is not None else 0,
            'query_execution_times': {
                'min_ms': float(round(min(query_times), 2)) if query_times else 0,
                'max_ms': float(round(max(query_times), 2)) if query_times else 0,
                'median_ms': float(round(median(query_times), 2)) if query_times else 0,
                'average_ms': float(round(mean(query_times), 2)) if query_times else 0
            }
        },
        'query_metrics_summary': {}
    }
    
    metric_names = ['execution_time', 'elapsed_time', 'result_count', 'result_size', 'error_count', 'warning_count']
    for metric_name in metric_names:
        values = [m[metric_name] for m in query_metrics_list if m[metric_name] is not None]
        if values:
            report['query_metrics_summary'][metric_name] = {
                'min': float(round(min(values), 2)) if metric_name in ['execution_time', 'elapsed_time'] else int(min(values)),
                'max': float(round(max(values), 2)) if metric_name in ['execution_time', 'elapsed_time'] else int(max(values)),
                'median': float(round(median(values), 2)) if metric_name in ['execution_time', 'elapsed_time'] else int(median(values)),
                'average': float(round(mean(values), 2)) if metric_name in ['execution_time', 'elapsed_time'] else int(max(values)),
                'valid_values': int(len(values))
            }
    
    report['query_profile_summary'] = {}
    valid_profiles = [p for p in profiles_list if p and 'phaseTimes' in p]
    if valid_profiles:
        report['query_profile_summary']['num_profiled_queries'] = int(len(valid_profiles))
        phase_stats = {}
        all_phases = set()
        for p in valid_profiles:
            all_phases.update(p['phaseTimes'].keys())
        
        for phase in sorted(all_phases):
            phase_times = [parse_phase_time(p['phaseTimes'].get(phase, None)) for p in valid_profiles]
            valid_phase_times = [t for t in phase_times if t > 0]
            if valid_phase_times:
                phase_stats[phase] = {
                    'min_ms': float(round(min(valid_phase_times), 2)),
                    'max_ms': float(round(max(valid_phase_times), 2)),
                    'median_ms': float(round(median(valid_phase_times), 2)),
                    'average_ms': float(round(mean(valid_phase_times), 2)),
                    'valid_iterations': int(len(valid_phase_times))
                }
        report['query_profile_summary']['phase_stats'] = phase_stats
    else:
        report['query_profile_summary']['num_profiled_queries'] = 0
        report['query_profile_summary']['phase_stats'] = {}
    
    extreme_queries_data = get_extreme_queries(query_times, profiles_list, query_timestamps)
    report['extreme_queries'] = {
        'slowest_queries': extreme_queries_data['slowest_queries'],
        'fastest_queries': extreme_queries_data['fastest_queries']
    }
    if include_timeline:
        report['query_timeline'] = extreme_queries_data['timeline']
    
    report['ping_latency_summary'] = {service: {
        'min_ms': float(round(stats['min'], 2)),
        'max_ms': float(round(stats['max'], 2)),
        'median_ms': float(round(stats['median'], 2)),
        'average_ms': float(round(stats['average'], 2)),
        'num_pings': int(stats['count'])
    } for service, stats in latency_summary.items()}
    
    report['detailed_ping_report'] = ping_summary
    report['network_diagnostics'] = network_diagnostics
    
    return report

def log_report(report):
    """Log the report in the original format to stdout."""
    print("\n=== Couchbase Query Tester Report ===")
    if 'tool_version' in report:
        print(f"Version: {report['tool_version']}")
    
    print("\n=== Timing Statistics (ms) ===")
    print(f"Initial Connection Time: {report['timing_statistics']['initial_connection_time_ms']:.2f} ms")
    
    print("\nQuery Execution Times:")
    qet = report['timing_statistics']['query_execution_times']
    print(f"  Min: {qet['min_ms']:.2f} ms")
    print(f"  Max: {qet['max_ms']:.2f} ms")
    print(f"  Median: {qet['median_ms']:.2f} ms")
    print(f"  Average: {qet['average_ms']:.2f} ms")
    
    print("\nQuery Metrics Summary:")
    for metric_name, stats in report['query_metrics_summary'].items():
        print(f"  {metric_name}:")
        print(f"    Min: {stats['min']}")
        print(f"    Max: {stats['max']}")
        print(f"    Median: {stats['median']}")
        print(f"    Average: {stats['average']}")
        print(f"    Valid Values: {stats['valid_values']}")
    
    print("\nQuery Profile Summary:")
    ps = report['query_profile_summary']
    print(f"  Number of profiled queries: {ps['num_profiled_queries']}")
    for phase, stats in ps['phase_stats'].items():
        print(f"  {phase} phase:")
        print(f"    Min: {stats['min_ms']:.2f} ms")
        print(f"    Max: {stats['max_ms']:.2f} ms")
        print(f"    Median: {stats['median_ms']:.2f} ms")
        print(f"    Average: {stats['average_ms']:.2f} ms")
        print(f"    Valid Iterations: {stats['valid_iterations']}")
    
    print("\nExtreme Queries (Top 1% Slowest and Bottom 1% Fastest):")
    eq = report['extreme_queries']
    print("  Slowest Queries:")
    for query in eq['slowest_queries']:
        print(f"    Iteration {query['iteration']}: {query['execution_time_ms']:.2f} ms")
        print(f"      Profile: {json.dumps(query['profile'], indent=2)}")
    print("  Fastest Queries:")
    for query in eq['fastest_queries']:
        print(f"    Iteration {query['iteration']}: {query['execution_time_ms']:.2f} ms")
        print(f"      Profile: {json.dumps(query['profile'], indent=2)}")
    
    if 'query_timeline' in report:
        print("\nQuery Timeline:")
        for entry in report['query_timeline']:
            print(f"  Timestamp: {entry['dt']}, Execution Time: {entry['v']:.2f} ms, Slowest: {entry['slowest']}, Fastest: {entry['fastest']}")
    
    print("\nOnline Chart Data:")
    for entry in report['onlineChartData']:
        print(f"  Timestamp: {entry['dt']}, Sum: {entry['sum']}, Min: {entry['min']:.2f} ms, Max: {entry['max']:.2f} ms, Mean: {entry['mean']:.2f} ms")
    
    print("\nPing Latency Summary (ms):")
    for service, stats in report['ping_latency_summary'].items():
        print(f"  {service} Service:")
        print(f"    Min Latency: {stats['min_ms']:.2f} ms")
        print(f"    Max Latency: {stats['max_ms']:.2f} ms")
        print(f"    Median Latency: {stats['median_ms']:.2f} ms")
        print(f"    Average Latency: {stats['average_ms']:.2f} ms")
        print(f"    Number of Pings: {stats['num_pings']}")
    
    print("\nDetailed Ping Report:")
    for ping_info in report['detailed_ping_report']:
        print(f"  Iteration {ping_info['iteration']}:")
        print(f"    Ping ID: {ping_info['id']}")
        print(f"    SDK: {ping_info['sdk']}")
        print(f"    Version: {ping_info['version']}")
        print("    Endpoints:")
        for service, endpoint in ping_info['endpoints'].items():
            print(f"      {service}:")
            print(f"        Endpoint ID: {endpoint['id']}")
            print(f"        Local Address: {endpoint['local']}")
            print(f"        Remote Address: {endpoint['remote']}")
            print(f"        Latency: {endpoint['latency_ms']:.2f} ms")
            print(f"        State: {endpoint['state']}")
    
    print("\n=== Network Diagnostics ===")
    nd = report['network_diagnostics']
    if not nd:
        print("Network diagnostics skipped.")
    else:
        print(f"Host: {nd['host']}")
        print(f"\nTraceroute:\n{nd['traceroute']}")
        print(f"\nVerbose Ping:\n{nd['ping']}")
        print(f"\nSRV Records:\n{json.dumps(nd['srv_records'], indent=2) if isinstance(nd['srv_records'], list) else nd['srv_records']}")
        if isinstance(nd.get('tcp_tests'), list):
            print("\nTCP Connection Tests (via SRV nodes):")
            for node in nd['tcp_tests']:
                print(f"  Node {node['host']}:{node['port']}:")
                for test in node.get('tcp_tests', []):
                    if 'ip' in test:
                        print(f"    IP {test['ip']}: Success={test['success']}, Latency={test['latency_ms']:.2f} ms, Error={test['error']}")
                    else:
                        print(f"    Error: {test.get('error', 'Unknown')}")
        elif isinstance(nd.get('tcp_tests'), dict):
            print("\nTCP Connection Tests to Common Capella Ports:")
            for endpoint, test in nd['tcp_tests'].items():
                print(f"  {endpoint}: Success={test['success']}, Latency={test['latency_ms']:.2f} ms, Error={test['error']}")
        else:
            print("\nNo TCP tests performed.")

def main():
    try:
        # Parse command-line arguments
        args = parse_arguments()
        CB_URL = args.url
        CB_USERNAME = os.getenv("CB_USERNAME", args.username)
        CB_PASSWORD = os.getenv("CB_PASSWORD", args.password)
        BUCKET_NAME = args.bucket
        NUM_ITERATIONS = args.num_iterations
        QUERY = args.query if args.query else f"SELECT * FROM `{BUCKET_NAME}`"
        JSON_OUTPUT = args.json
        REPORT_ONLY = args.report_only
        SKIP_DIAGNOSTICS = args.skip
        INCLUDE_TIMELINE = args.timeline

        # Configure logging for report-only mode
        if REPORT_ONLY:
            configure_logging(REPORT_ONLY)
        else:
            logger.info("Using query: %s", QUERY)

        # Extract hostname from URL
        parsed_url = urlparse(CB_URL)
        host = parsed_url.hostname
        if not REPORT_ONLY:
            logger.info("Extracted hostname: %s", host)

        # Run network diagnostics unless skipped
        network_diagnostics = {}
        if not SKIP_DIAGNOSTICS:
            if not REPORT_ONLY:
                logger.info("Running network diagnostics to %s", host)
            network_diagnostics = perform_network_diagnostics(host)
        else:
            if not REPORT_ONLY:
                logger.info("Skipping network diagnostics")

        # Lists to store timing metrics and ping results
        query_times = []
        query_metrics_list = []
        profiles_list = []
        ping_results = []
        query_timestamps = []
        conn_time = None

        # Establish single connection
        if not REPORT_ONLY:
            logger.info("Establishing single cluster connection")
        try:
            (cluster, ping_result), conn_time = connect_to_cluster(CB_URL, CB_USERNAME, CB_PASSWORD)
            ping_results.append(ping_result)
            if not REPORT_ONLY:
                logger.info("Initial connection time: %.2f ms", conn_time * 1000)
        except TimeoutException as e:
            error_report = {
                'tool_version': __version__,
                'onlineChartData': [],
                'error': str(e),
                'message': "Failed to connect to cluster due to timeout",
                'timeout': True,
                'cluster_url': CB_URL,
                'host': host
            }
            if JSON_OUTPUT:
                print(json.dumps(error_report, indent=2))
                sys.stdout.flush()
            else:
                log_report(error_report)
                sys.stdout.flush()
            return
        except CouchbaseException as e:
            error_report = {
                'tool_version': __version__,
                'onlineChartData': [],
                'error': str(e),
                'message': "Failed to connect to cluster",
                'timeout': False,
                'cluster_url': CB_URL,
                'host': host
            }
            if JSON_OUTPUT:
                print(json.dumps(error_report, indent=2))
                sys.stdout.flush()
            else:
                log_report(error_report)
                sys.stdout.flush()
            return

        # Run the query NUM_ITERATIONS times using the same connection
        try:
            for i in range(NUM_ITERATIONS):
                if not REPORT_ONLY:
                    logger.info("Starting iteration %d", i + 1)
                
                try:
                    query_start_time = time.time()
                    (metrics, profile), q_time = execute_query(cluster, QUERY, BUCKET_NAME)
                    query_times.append(q_time * 1000)
                    query_timestamps.append(query_start_time)
                    query_metrics_list.append(metrics)
                    profiles_list.append(profile)
                    if not REPORT_ONLY:
                        logger.info("Query execution time: %.2f ms", query_times[-1])
                        logger.info("Query metrics: %s", metrics)
                except CouchbaseException as e:
                    if not REPORT_ONLY:
                        logger.error("Skipping iteration %d due to query failure", i + 1)
                
                try:
                    ping_result = cluster.ping()
                    ping_results.append(ping_result)
                    if not REPORT_ONLY:
                        for service, endpoints in ping_result.endpoints.items():
                            for endpoint in endpoints:
                                logger.info(
                                    "%s service ping: %.2f ms to %s",
                                    service, (endpoint.latency.total_seconds() * 1000), endpoint.remote
                                )
                except CouchbaseException as e:
                    if not REPORT_ONLY:
                        logger.error("Ping failed in iteration %d: %s", i + 1, e)
                
                time.sleep(0.5)
        except KeyboardInterrupt:
            if not REPORT_ONLY:
                logger.info("Received interrupt, stopping iterations and generating report")

        # Close the cluster connection
        if not REPORT_ONLY:
            logger.debug("Closing cluster connection")
        try:
            cluster.close()
        except Exception as e:
            if not REPORT_ONLY:
                logger.error("Error closing cluster connection: %s", e)

        # Generate and output report
        ping_summary, latency_summary = summarize_ping_metrics(ping_results)
        report = generate_report(query_times, conn_time, query_metrics_list, profiles_list, ping_summary, latency_summary, network_diagnostics, query_timestamps, INCLUDE_TIMELINE, tool_version=__version__)
        
        if JSON_OUTPUT:
            print(json.dumps(report, indent=2))
            sys.stdout.flush()
        else:
            log_report(report)
            sys.stdout.flush()

    except Exception as e:
        error_report = {
            'tool_version': __version__,
            'onlineChartData': [],
            'error': str(e),
            'message': "Script failed unexpectedly",
            'timeout': isinstance(e, TimeoutException),
            'cluster_url': CB_URL,
            'host': host
        }
        if JSON_OUTPUT:
            print(json.dumps(error_report, indent=2))
            sys.stdout.flush()
        else:
            log_report(error_report)
            sys.stdout.flush()
        raise

if __name__ == "__main__":
    main()