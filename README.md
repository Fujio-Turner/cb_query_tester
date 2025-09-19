# Couchbase Query Performance Tester

## Overview

The `cb_query_tester.py` script is a Python tool designed to test and analyze the performance of N1QL queries against a Couchbase Capella cluster. It executes a specified query multiple times, collects detailed performance metrics (e.g., execution time, elapsed time, result count), and generates a comprehensive report. The script also performs network diagnostics (e.g., traceroute, ping, DNS SRV resolution) to identify connectivity issues and groups query execution times into 30-second intervals for charting, addressing the problem of visualizing large datasets (e.g., 1000 query runs).

### Problems Solved
- **Performance Analysis**: Measures query execution times (client-side and server-side), identifying slow and fast queries to optimize query performance.
- **Network Troubleshooting**: Diagnoses connectivity issues to Couchbase Capella clusters with ping, traceroute, and TCP connection tests.
- **Scalable Visualization**: Groups large numbers of query runs (e.g., 1000 iterations) into 30-second intervals to create manageable charts, preventing overcrowded x-axes.
- **Error Handling**: Captures and reports connection timeouts and query failures, aiding in debugging deployment issues.
- **Flexible Output**: Supports JSON and human-readable reports, with options to suppress logs or skip diagnostics for automation.

This script is ideal for developers, database administrators, and DevOps engineers who need to benchmark query performance, diagnose network issues, or visualize latency trends in Couchbase Capella environments.

## Prerequisites
- **Python**: Version 3.8 or higher (tested with 3.13.3).
- **Dependencies**:
  - `couchbase`: For interacting with Couchbase Capella (`pip install couchbase`).
  - `numpy`: For calculating extreme queries (`pip install numpy`).
  - `dnspython`: Optional, for DNS SRV resolution (`pip install dnspython`). Required unless `-s` is used.
- **Couchbase Capella**:
  - A valid cluster URL (e.g., `couchbases://cb.<cluster-id>.cloud.couchbase.com`).
  - Username and password with appropriate permissions.
  - A bucket (e.g., `travel-sample`) for querying.
- **Network**: Ensure the client’s IP is whitelisted in Couchbase Capella’s access settings.

## Usage
Run the script from the command line with the required arguments:

```bash
python3 query_tester_10.py -U <cluster-url> -u <username> -p <password> -b <bucket> [options]
```

### Command-Line Arguments
| Flag | Long Form | Description | Required | Default |
|------|-----------|-------------|----------|---------|
| `-U` | `--url` | Couchbase Capella cluster URL (e.g., `couchbases://cb.<cluster-id>.cloud.couchbase.com`). | Yes | None |
| `-u` | `--username` | Username for authentication. Can also be set via `CB_USERNAME` environment variable. | Yes | None |
| `-p` | `--password` | Password for authentication. Can also be set via `CB_PASSWORD` environment variable. | Yes | None |
| `-b` | `--bucket` | Bucket name to query (e.g., `travel-sample`). | Yes | None |
| `-n` | `--num-iterations` | Number of times to execute the query (e.g., `1000` for extensive testing). | No | `10` |
| `-q` | `--query` | Custom N1QL query to execute (e.g., `SELECT COUNT(1) FROM \`travel-sample\` WHERE city IS NOT MISSING`). | No | `SELECT * FROM \`<bucket>\`` |
| `-j` | `--json` | Output the report in JSON format instead of human-readable text. | No | False |
| `-r` | `--report-only` | Suppress all logs except the final report, useful for automation. | No | False |
| `-s` | `--skip` | Skip network diagnostics (DNS, traceroute, ping) to focus on query execution. | No | False |
| `-t` | `--timeline` | Include a `query_timeline` array in the report with per-query timestamps and execution times, including `slowest` and `fastest` flags. | No | False |

### Output Structure
The script generates a report in JSON (with `-j`) or human-readable text, containing:

- **`onlineChartData`**: Array of query performance metrics grouped by 30-second intervals, designed for charting on `https://kanaries.net/tools/json-to-chart`. Each entry includes:
  - `dt`: Timestamp (ISO 8601, UTC, e.g., `2025-09-19T04:55:30Z`), floored to the nearest 30 seconds.
  - `sum`: Number of queries executed in the interval (integer).
  - `min`: Minimum client-side elapsed time (ms, float) in the interval.
  - `max`: Maximum client-side elapsed time (ms, float) in the interval.
  - `mean`: Average client-side elapsed time (ms, float) in the interval.
- **`query_timeline`** (if `-t` is used): Array of per-query metrics, each with:
  - `dt`: Timestamp of query execution (ISO 8601, UTC, e.g., `2025-09-19T04:55:30.123456Z`).
  - `v`: Client-side elapsed time (ms, float).
  - `slowest`: `true` if in the top 1% slowest queries.
  - `fastest`: `true` if in the bottom 1% fastest queries.
- **`timing_statistics`**:
  - `initial_connection_time_ms`: Time to connect to the cluster (ms, float).
  - `query_execution_times`: Min, max, median, and average client-side elapsed times (ms, float).
- **`query_metrics_summary`**: Statistics for server-side metrics (e.g., `execution_time`, `elapsed_time`, `result_count`) with min, max, median, average, and valid values.
- **`query_profile_summary`**: Statistics for query phase times (e.g., `authorize`, `indexScan`) with min, max, median, average, and valid iterations.
- **`extreme_queries`**:
  - `slowest_queries`: Top 1% slowest queries with iteration, execution time, and decoded `phaseTimes`/`cpuTime`.
  - `fastest_queries`: Bottom 1% fastest queries with similar details.
- **`ping_latency_summary`**: Min, max, median, average, and count of ping latencies for each service (e.g., `query`, `kv`).
- **`detailed_ping_report`**: Detailed ping results per iteration.
- **`network_diagnostics`**: Traceroute, ping, DNS SRV records, and TCP connection tests (unless `-s` is used).

**Error Report** (on failure, e.g., timeout):
- `onlineChartData`: Empty array (`[]`).
- `error`: Error message (e.g., `LCB_ERR_TIMEOUT (201): The request timed out`).
- `message`: Description (e.g., `Failed to connect to cluster due to timeout`).
- `timeout`: `true` if a timeout occurred, else `false`.
- `cluster_url`: The provided URL.
- `host`: Extracted hostname.

## Examples
Below are example commands to demonstrate different use cases. Replace `<cluster-id>`, `<username>`, and `<password>` with your Couchbase Capella credentials.

### 1. Generate a Basic JSON Report
Run 10 iterations of the default query (`SELECT * FROM \`travel-sample\``) and output a JSON report:
```bash
python3 query_tester_10.py -U couchbases://cb.<cluster-id>.cloud.couchbase.com -u <username> -p <password> -b travel-sample -j > report.json
```
- **Output**: `report.json` with `onlineChartData`, `timing_statistics`, etc., but no `query_timeline` (since `-t` is not used).
- **Use Case**: Quick performance check with minimal output.

### 2. Skip Network Diagnostics
Run 100 iterations of a custom query, skipping diagnostics to focus on query performance:
```bash
python3 query_tester_10.py -U couchbases://cb.<cluster-id>.cloud.couchbase.com -u <username> -p <password> -b travel-sample -j -q 'SELECT COUNT(1) FROM `travel-sample` WHERE city IS NOT MISSING' -n 100 -s -r > report.json
```
- **Output**: `report.json` with `onlineChartData` (grouped by 30-second intervals), no `network_diagnostics`.
- **Use Case**: Faster execution for query-focused testing in automated pipelines.

### 3. Generate `onlineChartData` for Charting
Run 1000 iterations and include `query_timeline` for detailed analysis, with `onlineChartData` for charting:
```bash
python3 query_tester_10.py -U couchbases://cb.<cluster-id>.cloud.couchbase.com -u <username> -p <password> -b travel-sample -j -q 'SELECT COUNT(1) FROM `travel-sample` WHERE city IS NOT MISSING' -n 1000 -s -r -t > report.json
```
- **Output**: `report.json` with `onlineChartData` (~16–17 groups, each with ~50–60 queries) and `query_timeline` (1000 entries).
- **Charting**: Copy `onlineChartData` to `https://kanaries.net/tools/json-to-chart`, set `dt` as x-axis, and `mean` or `max` as y-axis to visualize latency trends.
- **Use Case**: Identify latency spikes in large-scale tests (e.g., max > 400 ms).

### 4. Debug Connectivity with Full Diagnostics
Run a single iteration with diagnostics and human-readable output:
```bash
python3 query_tester_10.py -U couchbases://cb.<cluster-id>.cloud.couchbase.com -u <username> -p <password> -b travel-sample -q 'SELECT 1' -n 1 -t
```
- **Output**: Console logs with diagnostics (traceroute, ping, DNS SRV) and a text report including `onlineChartData` and `query_timeline`.
- **Use Case**: Troubleshoot connection timeouts or network issues (e.g., high ping latency).

### 5. Minimal Test for Timeout Debugging
Run a single simple query to verify connectivity:
```bash
python3 query_tester_10.py -U couchbases://cb.<cluster-id>.cloud.couchbase.com -u <username> -p <password> -b travel-sample -j -q 'SELECT 1' -n 1 -s -r -t > report.json
```
- **Output**: `report.json` with minimal data, useful for checking if timeouts persist.
- **Use Case**: Quick validation of cluster access and credentials.

## Notes
- **Timeouts**: If you encounter `LCB_ERR_TIMEOUT`, verify IP whitelisting, credentials, and network connectivity. Run without `-r` to see detailed logs.
- **Charting**: Use `onlineChartData` for `https://kanaries.net/tools/json-to-chart`. For 1000 iterations (~500 seconds with 0.5s delays), expect ~16–17 groups. Use `mean` or `max` to spot spikes (e.g., >400 ms).
- **Performance**: Client-side times (e.g., 329.02–450.41 ms) may be higher than server-side times (e.g., 1.45–2.2 ms) due to network latency. Check `extreme_queries` for details.
- **Dependencies**: Install `numpy` and `couchbase`. Install `dnspython` if not using `-s`.

For further assistance, contact your Couchbase Capella administrator or refer to the [Couchbase SDK documentation](https://docs.couchbase.com/python-sdk/current/hello-world/start-using-sdk.html).

