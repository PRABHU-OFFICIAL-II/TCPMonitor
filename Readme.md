# TCPMonitor

A Java-based network diagnostic utility that watches application log files for critical errors and simultaneously manages rolling `tcpdump` packet captures. When a configured error string is detected, it immediately triggers a final targeted capture and fires a webhook alert — giving you a precise network snapshot at the exact moment of failure.

---

## How It Works

1. Start TCPMonitor with a `config.json` file.
2. One monitor thread is launched per configured log file. Each thread tails the file from EOF, watching for any matching error string.
3. In parallel, the capture thread cycles through rolling `.pcap` files (each one lasting `max_time_threshold` ms), keeping only the most recent `tcp_dump_count` files on disk.
4. The moment a critical error is detected:
   - The current rolling capture is stopped immediately.
   - All rolling captures on disk are **preserved** (no further deletions).
   - A final capture runs for `final_capture_duration` ms.
   - A JSON webhook alert is sent to `alert_webhook_url` (if configured).
5. The program exits and prints a summary of lines read and errors found.

---

## Requirements

- Java 8 or higher
- `tcpdump` installed and on the `PATH` (Linux/macOS: usually pre-installed; requires `CAP_NET_RAW` or `sudo`)
- Maven 3.6+ (only needed to build from source)

---

## Building

```bash
mvn clean package
```

This produces a self-contained fat JAR at:

```
target/TCPMonitor-1.0-SNAPSHOT.jar
```

---

## Running

```bash
java -jar target/TCPMonitor-1.0-SNAPSHOT.jar config.json
```

Logs are written to the console and to a rolling file under `logs/tcpmonitor.log`.

---

## Configuration

Copy `config.example.json` to `config.json` and edit as needed.

```json
{
  "log_paths": [
    "/var/log/app/application.log",
    "/var/log/app/error.log"
  ],

  "tcpdump_output_dir": "/var/captures/tcpmonitor",

  "error_strings": [
    "CriticalError",
    "NetworkTimeout",
    "Fatal",
    "OutOfMemoryError"
  ],

  "ip_filters": ["192.168.1.100", "10.0.0.50"],

  "port_filters": [443, 8080],

  "capture_mode": "ALL_TRAFFIC_FOR_IPS",

  "interface": "eth0",

  "max_time_threshold": 30000,

  "tcp_dump_count": 5,

  "final_capture_duration": 120000,

  "alert_webhook_url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
}
```

### All Configuration Keys

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `log_paths` | array of strings | Yes* | — | List of log file paths to monitor simultaneously. Each gets its own monitor thread. |
| `log_path` | string | Yes* | — | Single log file path. Fallback if `log_paths` is not set. |
| `tcpdump_output_dir` | string | Yes | — | Directory where `.pcap` capture files are written. Created if it does not exist. |
| `error_strings` | array of strings | Yes* | — | List of strings that trigger the final capture. Matching is case-insensitive. |
| `error_string` | string | Yes* | — | Single trigger string. Fallback if `error_strings` is not set. |
| `ip_filters` | array of strings | No | `[]` | IP addresses to include in the BPF capture filter. |
| `port_filters` | array of integers | No | `[]` | TCP/UDP port numbers to include in the BPF capture filter. |
| `capture_mode` | string | No | `ALL_TRAFFIC_FOR_IPS` | `ALL_TRAFFIC_FOR_IPS` captures traffic to/from any listed IP. `BETWEEN_IPS` captures only traffic between the first two listed IPs. |
| `interface` | string | No | *(tcpdump default)* | Network interface to capture on (e.g. `eth0`, `en0`). |
| `max_time_threshold` | long (ms) | No | `30000` | Duration of each rolling capture window in milliseconds. |
| `tcp_dump_count` | int | No | `5` | Number of rolling capture files to keep on disk before pruning the oldest. |
| `final_capture_duration` | long (ms) | No | `120000` | How long the final post-error capture runs in milliseconds. |
| `alert_webhook_url` | string | No | `""` | HTTP endpoint to POST a JSON alert to when the critical error fires. Compatible with Slack, PagerDuty, and any generic webhook receiver. |

*One of `log_paths`/`log_path` and one of `error_strings`/`error_string` must be provided.

---

## Output Files

Capture files are written to `tcpdump_output_dir` with timestamp-based names so they are unambiguous during post-mortem analysis:

```
tcpdump_20260523T143012.pcap      ← rolling capture
tcpdump_20260523T143042.pcap      ← rolling capture
tcpdump_final_20260523T143105.pcap ← final capture after error
```

Application logs are written to:

```
logs/tcpmonitor.log               ← current log
logs/tcpmonitor.2026-05-22.log    ← previous day (kept for 30 days)
```

---

## Webhook Alert Payload

When an error is detected, TCPMonitor sends a `POST` request with `Content-Type: application/json`:

```json
{
  "text": "TCPMonitor: Critical error detected at 2026-05-23T14:31:05. Final capture: /var/captures/tcpdump_final_20260523T143105.pcap",
  "timestamp": "2026-05-23T14:31:05",
  "lines_read": 48210,
  "errors_found": 3
}
```

The `text` field is compatible with Slack's incoming webhook format out of the box.

---

## Changelog

### v1.0 — Initial Release
- Real-time log file tailing from EOF.
- Single `log_path` configuration.
- Rolling tcpdump captures with configurable window and file count.
- IP filtering with `BETWEEN_IPS` and `ALL_TRAFFIC_FOR_IPS` modes.
- Automatic pruning of oldest capture files.
- Final 2-minute capture triggered on critical error.
- Sequential capture filenames (`tcpdump_1.pcap`, `tcpdump_2.pcap`, ...).

### v1.1 — Robustness & Scalability Enhancements

#### Bug Fixes
- **Thread-safe counters**: `totalLinesRead` and `totalErrorsFound` changed from plain `int` to `AtomicInteger`, eliminating a data race between the monitor and main threads.
- **Correct log seek**: Replaced `BufferedReader.skip(file.length())` (skips characters) with `RandomAccessFile.seek(file.length())` (seeks by bytes), fixing potential misalignment on UTF-8 logs with multi-byte characters.
- **Configurable final capture duration**: The final post-error capture duration was hardcoded at 120 seconds. It is now controlled by the `final_capture_duration` config key.
- **JVM shutdown hook**: A shutdown hook now destroys all spawned `tcpdump` child processes when the JVM exits via SIGTERM, Ctrl+C, or any other signal — preventing orphaned capture processes.

#### Robustness Improvements
- **Log rotation handling**: The monitor thread now detects when a log file shrinks (rotation/truncation) and automatically rewinds to byte 0 to continue monitoring the new content, rather than silently reading nothing.
- **Config validation**: All configuration values are validated before any threads are started, with clear error messages for missing required keys, invalid `capture_mode` values, and out-of-range thresholds.
- **tcpdump startup failure detection**: After spawning each `tcpdump` process, the tool waits 500 ms and checks `proc.isAlive()`. If the process has already exited, the exit code is logged and the run is aborted — rather than silently failing.
- **Timestamp-based capture filenames**: Capture files are now named with an ISO-8601 timestamp (e.g. `tcpdump_20260523T143012.pcap`) instead of sequential numbers, making post-mortem analysis unambiguous.

#### New Features
- **Multiple log files** (`log_paths`): Accepts an array of log file paths. A dedicated monitor thread is spawned for each file, so all logs are watched simultaneously.
- **Port filtering** (`port_filters`): Accepts an array of port numbers. These are combined into the tcpdump BPF filter expression alongside the existing IP filters (e.g. `(host 10.0.0.1) and (port 443 or port 8080)`).
- **Webhook alerts** (`alert_webhook_url`): After the final capture completes, TCPMonitor sends an HTTP POST with a JSON payload to the configured URL. Compatible with Slack, PagerDuty, and generic webhook receivers.
- **Structured logging**: All `System.out.println` calls replaced with SLF4J + Logback. Every log line now includes a timestamp, severity level, and thread name. Output goes to both console and a daily rolling log file (`logs/tcpmonitor.log`, 30-day retention).
- **Preserve all rolling captures on error**: Previously, rolling captures continued to be pruned after an error was detected. Now, once a critical error fires, all capture files on disk are retained in full for forensic use.

---

## Project Structure

```
TCPMonitor/
├── src/
│   └── main/
│       ├── java/com/informatica/
│       │   └── TCPMonitor.java        # Main application
│       └── resources/
│           └── logback.xml            # Logging configuration
├── config.example.json                # Annotated example configuration
├── pom.xml                            # Maven build (Java 8, fat JAR via shade plugin)
└── Readme.md
```

---

## License

Internal tool — Informatica.
