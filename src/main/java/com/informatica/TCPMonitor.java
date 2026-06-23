package com.informatica;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.*;

public class TCPMonitor {

    private static final Logger log = LoggerFactory.getLogger(TCPMonitor.class);

    private static final AtomicBoolean stopProgram   = new AtomicBoolean(false);
    private static final AtomicBoolean mainErrorFound = new AtomicBoolean(false);
    private static final AtomicInteger totalLinesRead  = new AtomicInteger(0);
    private static final AtomicInteger totalErrorsFound = new AtomicInteger(0);

    // All spawned child processes — cleaned up by shutdown hook and finally blocks
    private static final List<Process> processRegistry = Collections.synchronizedList(new ArrayList<>());

    private static int          tcpDumpCountLimit;
    private static long         maxTimeThreshold;
    private static long         finalCaptureDuration;
    private static String       captureInterface;
    private static CaptureMode  currentCaptureMode;
    private static List<Integer> portFilters;
    private static String       alertWebhookUrl;
    private static TraceMode    traceMode;
    private static String       sessionRunIdRegex;
    private static String       sessionStartMarker;
    private static String       sessionEndMarker;
    private static List<String> sessionIpFilters;
    private static List<String> sessionErrorStrings;

    private enum CaptureMode {
        BETWEEN_IPS, ALL_TRAFFIC_FOR_IPS
    }

    private enum TraceMode {
        DEFAULT, SESSION
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Config
    // ─────────────────────────────────────────────────────────────────────────

    private static class CaptureConfig {
        final List<String>  logPaths;        // literal paths — monitored immediately
        final List<String>  watchPatterns;   // wildcard patterns — only new arrivals monitored
        final String        outputDir;
        final List<String>  errorStrings;
        final List<String>  ipFilters;
        final List<Integer> portFilters;
        final CaptureMode   captureMode;
        final String        iface;
        final long          maxTimeThreshold;
        final int           tcpDumpCountLimit;
        final long          finalCaptureDuration;
        final String        alertWebhookUrl;
        final TraceMode     traceMode;
        final String        sessionLogPattern;
        final String        sessionStartMarker;
        final String        sessionEndMarker;
        final String        sessionRunIdRegex;

        CaptureConfig(List<String> logPaths, List<String> watchPatterns, String outputDir,
                      List<String> errorStrings, List<String> ipFilters, List<Integer> portFilters,
                      CaptureMode captureMode, String iface, long maxTimeThreshold,
                      int tcpDumpCountLimit, long finalCaptureDuration, String alertWebhookUrl,
                      TraceMode traceMode, String sessionLogPattern, String sessionStartMarker,
                      String sessionEndMarker, String sessionRunIdRegex) {
            this.logPaths            = logPaths;
            this.watchPatterns       = watchPatterns;
            this.outputDir           = outputDir;
            this.errorStrings        = errorStrings;
            this.ipFilters           = ipFilters;
            this.portFilters         = portFilters;
            this.captureMode         = captureMode;
            this.iface               = iface;
            this.maxTimeThreshold    = maxTimeThreshold;
            this.tcpDumpCountLimit   = tcpDumpCountLimit;
            this.finalCaptureDuration = finalCaptureDuration;
            this.alertWebhookUrl     = alertWebhookUrl;
            this.traceMode           = traceMode;
            this.sessionLogPattern   = sessionLogPattern;
            this.sessionStartMarker  = sessionStartMarker;
            this.sessionEndMarker    = sessionEndMarker;
            this.sessionRunIdRegex   = sessionRunIdRegex;
        }
    }

    /**
     * Watches a directory for files newly created (or moved in) after startup that
     * match the given glob pattern. Pre-existing matches are snapshotted and ignored
     * so the monitor only reacts to genuinely new arrivals.
     */
    private static void watchDirectoryForNewFiles(String rawPattern, List<String> errorStrings,
                                                  ExecutorService executor) {
        Path patternPath = Paths.get(rawPattern);
        Path watchDir    = patternPath.getParent();
        String glob      = patternPath.getFileName().toString();
        if (watchDir == null) watchDir = Paths.get(".");

        // Wait up to 30 s for the directory itself to appear
        long deadline = System.currentTimeMillis() + 30_000;
        while (!Files.isDirectory(watchDir)) {
            if (System.currentTimeMillis() > deadline) {
                log.error("Watch directory never appeared, giving up: {}", watchDir);
                return;
            }
            try { Thread.sleep(500); } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); return;
            }
        }

        // Snapshot files already present so they are ignored
        Set<String> preExisting = new HashSet<>();
        try (DirectoryStream<Path> snap = Files.newDirectoryStream(watchDir, glob)) {
            for (Path p : snap) {
                if (Files.isRegularFile(p))
                    preExisting.add(p.toAbsolutePath().normalize().toString());
            }
        } catch (IOException e) {
            log.warn("Could not snapshot pre-existing files for '{}': {}", rawPattern, e.getMessage());
        }
        log.info("Watch pattern '{}': ignoring {} pre-existing file(s), waiting for new arrivals.",
                rawPattern, preExisting.size());

        PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + glob);

        try (WatchService watcher = FileSystems.getDefault().newWatchService()) {
            watchDir.register(watcher, StandardWatchEventKinds.ENTRY_CREATE);
            log.info("Watching '{}' for new files matching '{}'", watchDir, glob);

            while (!stopProgram.get()) {
                WatchKey key = watcher.poll(200, TimeUnit.MILLISECONDS);
                if (key == null) continue;

                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.OVERFLOW) continue;

                    @SuppressWarnings("unchecked")
                    Path filename  = ((WatchEvent<Path>) event).context();
                    if (!matcher.matches(filename)) continue;

                    Path fullPath  = watchDir.resolve(filename).toAbsolutePath().normalize();
                    String fullStr = fullPath.toString();

                    if (preExisting.contains(fullStr)) continue; // was there at startup
                    if (!Files.isRegularFile(fullPath)) continue;

                    log.info("New file detected, starting monitor: {}", fullStr);
                    executor.submit(() -> monitorLogFile(fullStr, errorStrings));
                }

                if (!key.reset()) {
                    log.warn("Watch directory no longer accessible: {}", watchDir);
                    break;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.info("Directory watcher interrupted for pattern: {}", rawPattern);
        } catch (IOException e) {
            log.error("Directory watcher error for '{}': {}", rawPattern, e.getMessage(), e);
        }
    }

    private static CaptureConfig parseAndValidate(String configPath) throws Exception {
        File configFile = new File(configPath);
        if (!configFile.exists())
            throw new IllegalArgumentException("Config file not found: " + configPath);

        JSONObject cfg = new JSONObject(new String(Files.readAllBytes(configFile.toPath())));

        // log_paths array with fallback to singular log_path
        // Entries without * or ? are literal paths; entries with * or ? become watch patterns
        // (only files arriving after startup are monitored for wildcard entries).
        List<String> rawLogPaths = new ArrayList<>();
        JSONArray logPathsArr = cfg.optJSONArray("log_paths");
        if (logPathsArr != null && logPathsArr.length() > 0) {
            for (int i = 0; i < logPathsArr.length(); i++) rawLogPaths.add(logPathsArr.getString(i));
        } else if (cfg.has("log_path")) {
            rawLogPaths.add(cfg.getString("log_path"));
        } else {
            throw new IllegalArgumentException("Config must have 'log_paths' (array) or 'log_path'");
        }

        List<String> logPaths      = new ArrayList<>();
        List<String> watchPatterns = new ArrayList<>();
        for (String raw : rawLogPaths) {
            if (raw.contains("*") || raw.contains("?")) {
                watchPatterns.add(raw);
            } else {
                logPaths.add(raw);
            }
        }
        if (logPaths.isEmpty() && watchPatterns.isEmpty()) {
            throw new IllegalArgumentException("Config must have at least one entry in 'log_paths'");
        }
        for (String p : logPaths) {
            if (!new File(p).exists()) log.warn("Log file does not exist yet (will wait): {}", p);
        }
        for (String p : watchPatterns) {
            log.info("Wildcard watch pattern registered (new files only): {}", p);
        }

        if (!cfg.has("tcpdump_output_dir"))
            throw new IllegalArgumentException("Config must have 'tcpdump_output_dir'");
        String outputDir = cfg.getString("tcpdump_output_dir");

        List<String> errorStrings = new ArrayList<>();
        JSONArray errArr = cfg.optJSONArray("error_strings");
        if (errArr != null) {
            for (int i = 0; i < errArr.length(); i++) errorStrings.add(errArr.getString(i));
        } else {
            errorStrings.add(cfg.optString("error_string", ""));
        }
        if (errorStrings.stream().allMatch(s -> s == null || s.trim().isEmpty()))
            throw new IllegalArgumentException("Config must have at least one non-empty error string");

        List<String> ipFilters = new ArrayList<>();
        JSONArray ipArr = cfg.optJSONArray("ip_filters");
        if (ipArr != null) for (int i = 0; i < ipArr.length(); i++) ipFilters.add(ipArr.getString(i));

        List<Integer> portFilterList = new ArrayList<>();
        JSONArray portArr = cfg.optJSONArray("port_filters");
        if (portArr != null) for (int i = 0; i < portArr.length(); i++) portFilterList.add(portArr.getInt(i));

        String captureModeStr = cfg.optString("capture_mode", "ALL_TRAFFIC_FOR_IPS").toUpperCase();
        CaptureMode captureMode;
        try {
            captureMode = CaptureMode.valueOf(captureModeStr);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Invalid capture_mode '" + captureModeStr + "'. Valid: BETWEEN_IPS, ALL_TRAFFIC_FOR_IPS");
        }

        String iface = cfg.optString("interface", "");

        long maxTime = cfg.optLong("max_time_threshold", 30000L);
        if (maxTime <= 0) throw new IllegalArgumentException("max_time_threshold must be > 0");

        int countLimit = cfg.optInt("tcp_dump_count", 5);
        if (countLimit <= 0) throw new IllegalArgumentException("tcp_dump_count must be > 0");

        long finalDuration = cfg.optLong("final_capture_duration", 120000L);
        if (finalDuration <= 0) throw new IllegalArgumentException("final_capture_duration must be > 0");

        String webhookUrl = cfg.optString("alert_webhook_url", "");

        // ── SESSION mode config ──────────────────────────────────────────────
        String traceModeStr = cfg.optString("trace_mode", "DEFAULT").toUpperCase();
        TraceMode traceMode;
        try {
            traceMode = TraceMode.valueOf(traceModeStr);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Invalid trace_mode '" + traceModeStr + "'. Valid: DEFAULT, SESSION");
        }
        String sessionLogPattern  = cfg.optString("session_log_pattern", "");
        String sessionStartMarker = cfg.optString("session_start_marker", "Run log file:");
        String sessionEndMarker   = cfg.optString("session_end_marker", "=== Completed Run");
        String sessionRunIdRegex  = cfg.optString("session_runid_regex", "runid(\\d+)");
        if (traceMode == TraceMode.SESSION && (sessionLogPattern == null || sessionLogPattern.trim().isEmpty())) {
            throw new IllegalArgumentException("session_log_pattern is required when trace_mode is SESSION");
        }

        return new CaptureConfig(logPaths, watchPatterns, outputDir, errorStrings, ipFilters,
                portFilterList, captureMode, iface, maxTime, countLimit, finalDuration, webhookUrl,
                traceMode, sessionLogPattern, sessionStartMarker, sessionEndMarker, sessionRunIdRegex);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Log monitoring
    // ─────────────────────────────────────────────────────────────────────────

    public static void monitorLogFile(String logFilePath, List<String> errorStrings) {
        File logFile = new File(logFilePath);
        log.info("Log monitor started: {}", logFilePath);

        // Wait up to 30 s for the file to appear, then give up
        long waitDeadline = System.currentTimeMillis() + 30_000;
        while (!logFile.exists()) {
            if (System.currentTimeMillis() > waitDeadline) {
                log.error("Log file never appeared, giving up: {}", logFilePath);
                return;
            }
            try { Thread.sleep(500); } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); return;
            }
        }

        long position = logFile.length(); // start at EOF — only tail new entries

        try {
            while (!stopProgram.get()) {
                long currentLength = logFile.length();

                // Log rotation: file shrank → reopen from byte 0
                if (currentLength < position) {
                    log.warn("Log rotation detected for {}. Rewinding to start.", logFilePath);
                    position = 0;
                }

                if (currentLength > position) {
                    try (RandomAccessFile raf = new RandomAccessFile(logFile, "r")) {
                        raf.seek(position);
                        String line;
                        while ((line = raf.readLine()) != null) {
                            totalLinesRead.incrementAndGet();

                            for (String err : errorStrings) {
                                if (err != null && !err.trim().isEmpty() &&
                                        line.toLowerCase().contains(err.trim().toLowerCase())) {
                                    totalErrorsFound.incrementAndGet();
                                    log.error("[{}] CRITICAL match '{}': {}", logFilePath, err, line);
                                    mainErrorFound.set(true);
                                    return;
                                }
                            }
                        }
                        position = raf.getFilePointer();
                    }
                }

                Thread.sleep(100);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.info("Log monitor interrupted: {}", logFilePath);
        } catch (Exception e) {
            log.error("Log monitor error for {}: {}", logFilePath, e.getMessage(), e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // TCP capture management
    // ─────────────────────────────────────────────────────────────────────────

    private static void startTcpDump(String tcpDumpDir, List<String> ipFilters) {
        LinkedList<File> rollingFiles = new LinkedList<>();
        List<Process> activeProcesses = new ArrayList<>();
        boolean errorOccurred = false;

        File dir = new File(tcpDumpDir);
        if (!dir.exists()) dir.mkdirs();

        try {
            if (mainErrorFound.get()) {
                log.info("Error detected before first capture — skipping.");
                errorOccurred = true;
            }

            // ── Start the very first capture ──
            Process currentProc = null;
            File currentFile = null;

            if (!errorOccurred) {
                currentFile = newCaptureFile(tcpDumpDir, "tcpdump");
                try {
                    currentProc = spawnTcpDump(ipFilters, currentFile);
                } catch (IOException e) {
                    log.error("Failed to launch tcpdump: {}", e.getMessage());
                    errorOccurred = true;
                }
                if (currentProc != null) {
                    Thread.sleep(500);
                    if (!currentProc.isAlive()) {
                        log.error("tcpdump exited immediately (exit={}). Check binary path and CAP_NET_RAW permission.",
                                currentProc.exitValue());
                        currentProc = null;
                        errorOccurred = true;
                    } else {
                        activeProcesses.add(currentProc);
                        processRegistry.add(currentProc);
                        rollingFiles.add(currentFile);
                        log.info("Capture started: {}", currentFile.getAbsolutePath());
                    }
                }
            }

            // ── Rolling capture loop ──
            while (!errorOccurred && currentProc != null) {
                long startTime = System.currentTimeMillis();

                // Monitor current capture window
                while (true) {
                    if (mainErrorFound.get()) {
                        log.info("Error detected mid-capture. Stopping: {}", currentFile.getName());
                        currentProc.destroy();
                        currentProc.waitFor(5, TimeUnit.SECONDS);
                        errorOccurred = true;
                        break;
                    }
                    if (System.currentTimeMillis() - startTime >= maxTimeThreshold) {
                        break; // window elapsed — fall through to gap-free handoff
                    }
                    Thread.sleep(100);
                }

                if (errorOccurred) break;

                // Gap-free handoff: spawn the NEXT capture BEFORE stopping the current one
                // so there is no window of unmonitored traffic between captures.
                // After spawning, wait until the next process has written the 24-byte pcap
                // global header — that proves it has opened the interface and is capturing —
                // before we destroy the current process.
                Process nextProc = null;
                File nextFile = null;
                if (!mainErrorFound.get()) {
                    nextFile = newCaptureFile(tcpDumpDir, "tcpdump");
                    try {
                        nextProc = spawnTcpDump(ipFilters, nextFile);
                        activeProcesses.add(nextProc);
                        processRegistry.add(nextProc);
                        rollingFiles.add(nextFile);
                        log.info("Next capture pre-started (gap-free handoff): {}", nextFile.getAbsolutePath());
                        waitUntilCapturing(nextFile, nextProc);
                    } catch (IOException e) {
                        log.error("Failed to pre-start next tcpdump: {}", e.getMessage());
                    }
                }

                // Now it is safe to stop the current capture — next is already writing packets.
                // Hold the old capture alive for an extra 2000 ms so any in-flight packets
                // that arrive at the OS ring buffer during process handoff are still recorded.
                log.info("Capture window elapsed: {}", currentFile.getName());
                Thread.sleep(2000);
                currentProc.destroy();
                currentProc.waitFor(5, TimeUnit.SECONDS);

                // Delete oldest rolling file only while no error has been seen
                if (rollingFiles.size() > tcpDumpCountLimit) {
                    File oldest = rollingFiles.poll();
                    if (oldest != null && oldest.exists() && oldest.delete()) {
                        log.info("Pruned old capture: {}", oldest.getName());
                    }
                }

                if (nextProc == null) {
                    if (mainErrorFound.get()) errorOccurred = true;
                    break;
                }

                if (!nextProc.isAlive()) {
                    log.error("Pre-started tcpdump exited immediately (exit={}). Check binary path and CAP_NET_RAW permission.",
                            nextProc.exitValue());
                    break;
                }

                // Check for errors that arrived during the handoff
                if (mainErrorFound.get()) {
                    log.info("Error detected during capture handoff. Stopping pre-started capture.");
                    nextProc.destroy();
                    nextProc.waitFor(5, TimeUnit.SECONDS);
                    errorOccurred = true;
                    break;
                }

                currentProc = nextProc;
                currentFile = nextFile;
            }

            // ── Final targeted capture ──
            if (errorOccurred || mainErrorFound.get()) {
                log.info("Starting final capture ({} ms)...", finalCaptureDuration);
                for (Process p : activeProcesses) p.destroy();

                File finalFile = newCaptureFile(tcpDumpDir, "tcpdump_final");
                try {
                    Process finalProc = spawnTcpDump(ipFilters, finalFile);
                    processRegistry.add(finalProc);

                    Thread.sleep(500);
                    if (!finalProc.isAlive()) {
                        log.error("Final tcpdump exited immediately (exit={}).", finalProc.exitValue());
                    } else {
                        log.info("Final capture → {}", finalFile.getAbsolutePath());
                        Thread.sleep(finalCaptureDuration);
                        finalProc.destroy();
                        finalProc.waitFor(5, TimeUnit.SECONDS);
                        log.info("Final capture complete.");
                    }
                } catch (Exception e) {
                    log.error("Final capture error: {}", e.getMessage(), e);
                }

                sendWebhookAlert(finalFile.getAbsolutePath());
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.info("tcpdump thread interrupted.");
        } catch (Exception e) {
            log.error("tcpdump thread error: {}", e.getMessage(), e);
        } finally {
            for (Process p : activeProcesses) p.destroy();
        }

        stopProgram.set(true);
        log.info("All captures stopped.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // tcpdump process helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Blocks until tcpdump has written at least 24 bytes (the pcap global header),
     * which proves it has opened the interface and is actively capturing.
     * Falls through after 3 s regardless so the handoff is never held up indefinitely.
     */
    private static void waitUntilCapturing(File pcapFile, Process proc) {
        long deadline = System.currentTimeMillis() + 3_000;
        while (System.currentTimeMillis() < deadline) {
            if (!proc.isAlive()) return; // process died — nothing to wait for
            if (pcapFile.exists() && pcapFile.length() > 24) return; // first real packet written = pcap socket confirmed active
            try { Thread.sleep(10); } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); return;
            }
        }
        log.warn("waitUntilCapturing: timed out after 3 s for {}", pcapFile.getName());
    }

    private static File newCaptureFile(String dir, String prefix) {
        String ts = new SimpleDateFormat("yyyyMMdd'T'HHmmss").format(new Date());
        return new File(dir, prefix + "_" + ts + ".pcap");
    }

    private static Process spawnTcpDump(List<String> ipFilters, File outputFile) throws IOException {
        List<String> cmd = new ArrayList<>();
        cmd.add("tcpdump");

        if (captureInterface != null && !captureInterface.isEmpty()) {
            cmd.add("-i");
            cmd.add(captureInterface);
        }

        cmd.add("-U"); // flush each packet to disk immediately — no userspace buffering
        cmd.add("-s");
        cmd.add("0");
        cmd.add("-w");
        cmd.add(outputFile.getAbsolutePath());

        String filter = buildFilterExpression(ipFilters);
        if (!filter.isEmpty()) cmd.add(filter);

        log.info("Exec: {}", String.join(" ", cmd));
        return new ProcessBuilder(cmd)
                .redirectErrorStream(true)
                .start();
    }

    private static String buildFilterExpression(List<String> ipFilters) {
        StringBuilder expr = new StringBuilder();

        if (ipFilters != null && !ipFilters.isEmpty()) {
            if (currentCaptureMode == CaptureMode.BETWEEN_IPS && ipFilters.size() >= 2) {
                expr.append("host ").append(ipFilters.get(0))
                    .append(" and host ").append(ipFilters.get(1));
            } else {
                expr.append("(");
                for (int i = 0; i < ipFilters.size(); i++) {
                    if (i > 0) expr.append(" or ");
                    expr.append("host ").append(ipFilters.get(i));
                }
                expr.append(")");
            }
        }

        if (portFilters != null && !portFilters.isEmpty()) {
            if (expr.length() > 0) expr.append(" and ");
            expr.append("(");
            for (int i = 0; i < portFilters.size(); i++) {
                if (i > 0) expr.append(" or ");
                expr.append("port ").append(portFilters.get(i));
            }
            expr.append(")");
        }

        return expr.toString();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Webhook alert
    // ─────────────────────────────────────────────────────────────────────────

    private static void sendWebhookAlert(String finalCapturePath) {
        if (alertWebhookUrl == null || alertWebhookUrl.isEmpty()) return;

        try {
            String ts = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss").format(new Date());
            // Use org.json to guarantee correct escaping
            JSONObject payload = new JSONObject();
            payload.put("text", "TCPMonitor: Critical error detected at " + ts +
                    ". Final capture: " + finalCapturePath.replace('\\', '/'));
            payload.put("timestamp", ts);
            payload.put("lines_read", totalLinesRead.get());
            payload.put("errors_found", totalErrorsFound.get());

            byte[] body = payload.toString().getBytes("UTF-8");

            URL url = new URL(alertWebhookUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setRequestProperty("Content-Length", String.valueOf(body.length));
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(body);
            }

            log.info("Webhook alert sent → HTTP {}", conn.getResponseCode());
            conn.disconnect();

        } catch (Exception e) {
            log.warn("Webhook alert failed: {}", e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SESSION trace mode
    // ─────────────────────────────────────────────────────────────────────────

    private static String extractRunId(String filename, String regex) {
        try {
            Pattern p = Pattern.compile(regex);
            Matcher m = p.matcher(filename);
            if (m.find() && m.groupCount() >= 1) return m.group(1);
        } catch (Exception e) {
            log.warn("extractRunId: invalid regex '{}': {}", regex, e.getMessage());
        }
        return null;
    }

    private static void watchForSessionFiles(String rawPattern, ExecutorService executor) {
        Path patternPath = Paths.get(rawPattern);
        Path watchDir    = patternPath.getParent();
        String glob      = patternPath.getFileName().toString();
        if (watchDir == null) watchDir = Paths.get(".");

        long deadline = System.currentTimeMillis() + 30_000;
        while (!Files.isDirectory(watchDir)) {
            if (System.currentTimeMillis() > deadline) {
                log.error("[SESSION] Watch directory never appeared: {}", watchDir);
                return;
            }
            try { Thread.sleep(500); } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); return;
            }
        }

        Set<String> preExisting = new HashSet<>();
        try (DirectoryStream<Path> snap = Files.newDirectoryStream(watchDir, glob)) {
            for (Path p : snap) {
                if (Files.isRegularFile(p))
                    preExisting.add(p.toAbsolutePath().normalize().toString());
            }
        } catch (IOException e) {
            log.warn("[SESSION] Could not snapshot pre-existing files for '{}': {}", rawPattern, e.getMessage());
        }
        log.info("[SESSION] Watching '{}' for new session log files, ignoring {} pre-existing.",
                rawPattern, preExisting.size());

        PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + glob);

        try (WatchService watcher = FileSystems.getDefault().newWatchService()) {
            watchDir.register(watcher, StandardWatchEventKinds.ENTRY_CREATE);

            while (!stopProgram.get()) {
                WatchKey key = watcher.poll(200, TimeUnit.MILLISECONDS);
                if (key == null) continue;

                for (WatchEvent<?> event : key.pollEvents()) {
                    if (event.kind() == StandardWatchEventKinds.OVERFLOW) continue;

                    @SuppressWarnings("unchecked")
                    Path filename  = ((WatchEvent<Path>) event).context();
                    if (!matcher.matches(filename)) continue;

                    Path fullPath  = watchDir.resolve(filename).toAbsolutePath().normalize();
                    String fullStr = fullPath.toString();
                    if (preExisting.contains(fullStr)) continue;
                    if (!Files.isRegularFile(fullPath)) continue;

                    log.info("[SESSION] New session log detected: {}", fullStr);
                    executor.submit(() -> monitorSessionFile(fullStr));
                }

                if (!key.reset()) {
                    log.warn("[SESSION] Watch directory no longer accessible: {}", watchDir);
                    break;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.info("[SESSION] Directory watcher interrupted for pattern: {}", rawPattern);
        } catch (IOException e) {
            log.error("[SESSION] Directory watcher error for '{}': {}", rawPattern, e.getMessage(), e);
        }
    }

    private static void monitorSessionFile(String logFilePath) {
        File logFile = new File(logFilePath);
        log.info("[SESSION] Monitor started for: {}", logFilePath);

        long waitDeadline = System.currentTimeMillis() + 30_000;
        while (!logFile.exists()) {
            if (System.currentTimeMillis() > waitDeadline) {
                log.error("[SESSION] Log file never appeared: {}", logFilePath);
                return;
            }
            try { Thread.sleep(500); } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); return;
            }
        }

        // Derive the per-session pcap filename by replacing the log file's extension
        String logFileName = logFile.getName();
        int dotIdx = logFileName.lastIndexOf('.');
        String baseName = (dotIdx >= 0) ? logFileName.substring(0, dotIdx) : logFileName;
        File pcapFile = new File(logFile.getParent(), baseName + ".pcap");

        String runId = extractRunId(logFileName, sessionRunIdRegex);
        if (runId != null) {
            log.info("[SESSION] runId={} → pcap: {}", runId, pcapFile.getAbsolutePath());
        } else {
            log.warn("[SESSION] Could not extract runId from '{}' using regex '{}'",
                    logFileName, sessionRunIdRegex);
        }

        Process captureProc = null;
        long position = 0L;
        boolean captureStarted = false;
        long errorStopAt = -1; // -1 = no error seen; >0 = epoch ms when capture must stop

        try {
            while (!stopProgram.get()) {

                // Error latch: if an error was found, wait 10 s then stop
                if (errorStopAt > 0 && System.currentTimeMillis() >= errorStopAt) {
                    log.info("[SESSION] 10-second post-error window elapsed, stopping capture for runId={}.", runId);
                    if (captureProc != null && captureProc.isAlive()) {
                        captureProc.destroy();
                        captureProc.waitFor(5, TimeUnit.SECONDS);
                    }
                    log.info("[SESSION] Session terminated by error for runId={}", runId);
                    return;
                }

                long currentLength = logFile.length();
                if (currentLength > position) {
                    try (RandomAccessFile raf = new RandomAccessFile(logFile, "r")) {
                        raf.seek(position);
                        String line;
                        while ((line = raf.readLine()) != null) {
                            if (!captureStarted) {
                                if (sessionStartMarker != null && !sessionStartMarker.isEmpty()
                                        && line.contains(sessionStartMarker)) {
                                    log.info("[SESSION] Start marker found in '{}', spawning capture → {}",
                                            logFileName, pcapFile.getName());
                                    try {
                                        captureProc = spawnTcpDump(sessionIpFilters, pcapFile);
                                        processRegistry.add(captureProc);
                                        captureStarted = true;
                                        log.info("[SESSION] Capture started: {}", pcapFile.getAbsolutePath());
                                    } catch (IOException e) {
                                        log.error("[SESSION] Failed to spawn capture for session {}: {}",
                                                logFileName, e.getMessage());
                                    }
                                }
                            } else {
                                // Check error strings (only after capture has started, so error latch
                                // is not set before the capture process even exists)
                                if (errorStopAt < 0 && sessionErrorStrings != null) {
                                    for (String err : sessionErrorStrings) {
                                        if (err != null && !err.trim().isEmpty()
                                                && line.toLowerCase().contains(err.trim().toLowerCase())) {
                                            log.error("[SESSION] Error string '{}' matched in '{}': {}",
                                                    err, logFileName, line);
                                            errorStopAt = System.currentTimeMillis() + 10_000;
                                            log.info("[SESSION] Capture will stop in 10 s for runId={}.", runId);
                                            break;
                                        }
                                    }
                                }

                                // End marker — normal session completion
                                if (sessionEndMarker != null && !sessionEndMarker.isEmpty()
                                        && line.contains(sessionEndMarker)) {
                                    log.info("[SESSION] End marker found in '{}', stopping capture.",
                                            logFileName);
                                    if (captureProc != null && captureProc.isAlive()) {
                                        captureProc.destroy();
                                        captureProc.waitFor(5, TimeUnit.SECONDS);
                                    }
                                    log.info("[SESSION] Session complete for runId={}", runId);
                                    return;
                                }
                            }
                        }
                        position = raf.getFilePointer();
                    }
                }
                Thread.sleep(100);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.info("[SESSION] Monitor interrupted for: {}", logFilePath);
        } catch (Exception e) {
            log.error("[SESSION] Monitor error for {}: {}", logFilePath, e.getMessage(), e);
        } finally {
            if (captureProc != null && captureProc.isAlive()) {
                captureProc.destroy();
                log.info("[SESSION] Capture process destroyed in finally for: {}", logFileName);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Entry point
    // ─────────────────────────────────────────────────────────────────────────

    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("Usage: java -jar TCPMonitor.jar <config.json>");
            System.exit(1);
        }

        CaptureConfig config;
        try {
            config = parseAndValidate(args[0]);
        } catch (Exception e) {
            System.err.println("Configuration error: " + e.getMessage());
            System.exit(1);
            return;
        }

        // Push config into statics used by worker methods
        maxTimeThreshold    = config.maxTimeThreshold;
        tcpDumpCountLimit   = config.tcpDumpCountLimit;
        finalCaptureDuration = config.finalCaptureDuration;
        currentCaptureMode  = config.captureMode;
        captureInterface    = config.iface;
        portFilters         = config.portFilters;
        alertWebhookUrl     = config.alertWebhookUrl;
        traceMode           = config.traceMode;
        sessionRunIdRegex   = config.sessionRunIdRegex;
        sessionStartMarker  = config.sessionStartMarker;
        sessionEndMarker    = config.sessionEndMarker;
        sessionIpFilters    = config.ipFilters;
        sessionErrorStrings = config.errorStrings;

        // Kill all child processes on JVM exit (SIGTERM, Ctrl+C, etc.)
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutdown hook: terminating {} tcpdump process(es).", processRegistry.size());
            for (Process p : processRegistry) {
                if (p.isAlive()) p.destroy();
            }
        }, "shutdown-hook"));

        // ── SESSION mode ─────────────────────────────────────────────────────
        if (traceMode == TraceMode.SESSION) {
            log.info("TCPMonitor starting in SESSION trace mode.");
            log.info("Session log pattern : {}", config.sessionLogPattern);
            log.info("Start marker        : {}", config.sessionStartMarker);
            log.info("End marker          : {}", config.sessionEndMarker);
            log.info("Run-ID regex        : {}", config.sessionRunIdRegex);
            log.info("IP filters          : {}", config.ipFilters);

            ExecutorService sessionExecutor = Executors.newCachedThreadPool();
            final String sessionPattern = config.sessionLogPattern;
            sessionExecutor.submit(() -> watchForSessionFiles(sessionPattern, sessionExecutor));

            while (!stopProgram.get()) {
                try { Thread.sleep(200); } catch (InterruptedException e) {
                    Thread.currentThread().interrupt(); break;
                }
            }
            sessionExecutor.shutdownNow();
            try {
                sessionExecutor.awaitTermination(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            log.info("SESSION mode terminated.");
            return;
        }

        // ── DEFAULT mode (unchanged) ──────────────────────────────────────────
        log.info("TCPMonitor starting.");
        log.info("Log files ({}): {}", config.logPaths.size(), config.logPaths);
        log.info("Watch patterns ({}): {}", config.watchPatterns.size(), config.watchPatterns);
        log.info("Output dir  : {}", config.outputDir);
        log.info("Error triggers: {}", config.errorStrings);
        log.info("IP filters  : {} | Port filters: {} | Mode: {}",
                config.ipFilters, config.portFilters, config.captureMode);
        log.info("Capture window: {} ms | Rolling limit: {} | Final duration: {} ms",
                config.maxTimeThreshold, config.tcpDumpCountLimit, config.finalCaptureDuration);

        // Cached pool: literal monitors + watcher threads + dynamically discovered log files
        ExecutorService executor = Executors.newCachedThreadPool();

        for (String logPath : config.logPaths) {
            final String path = logPath;
            executor.submit(() -> monitorLogFile(path, config.errorStrings));
        }
        for (String pattern : config.watchPatterns) {
            final String pat = pattern;
            executor.submit(() -> watchDirectoryForNewFiles(pat, config.errorStrings, executor));
        }
        executor.submit(() -> startTcpDump(config.outputDir, config.ipFilters));

        // Do NOT call executor.shutdown() here — the watcher threads submit new monitorLogFile
        // tasks dynamically and would get RejectedExecutionException if shutdown is called early.
        // Instead, block until startTcpDump sets stopProgram (it always does before returning),
        // then tear everything down.
        while (!stopProgram.get()) {
            try { Thread.sleep(200); } catch (InterruptedException e) {
                Thread.currentThread().interrupt(); break;
            }
        }
        executor.shutdownNow();
        try {
            executor.awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        log.info("Program terminated — lines read: {} | errors found: {}",
                totalLinesRead.get(), totalErrorsFound.get());
    }
}