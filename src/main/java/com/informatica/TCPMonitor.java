package com.informatica;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

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

    private enum CaptureMode {
        BETWEEN_IPS, ALL_TRAFFIC_FOR_IPS
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Config
    // ─────────────────────────────────────────────────────────────────────────

    private static class CaptureConfig {
        final List<String>  logPaths;
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

        CaptureConfig(List<String> logPaths, String outputDir, List<String> errorStrings,
                      List<String> ipFilters, List<Integer> portFilters, CaptureMode captureMode,
                      String iface, long maxTimeThreshold, int tcpDumpCountLimit,
                      long finalCaptureDuration, String alertWebhookUrl) {
            this.logPaths            = logPaths;
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
        }
    }

    private static CaptureConfig parseAndValidate(String configPath) throws Exception {
        File configFile = new File(configPath);
        if (!configFile.exists())
            throw new IllegalArgumentException("Config file not found: " + configPath);

        JSONObject cfg = new JSONObject(new String(Files.readAllBytes(configFile.toPath())));

        // log_paths array with fallback to singular log_path
        List<String> logPaths = new ArrayList<>();
        JSONArray logPathsArr = cfg.optJSONArray("log_paths");
        if (logPathsArr != null && logPathsArr.length() > 0) {
            for (int i = 0; i < logPathsArr.length(); i++) logPaths.add(logPathsArr.getString(i));
        } else if (cfg.has("log_path")) {
            logPaths.add(cfg.getString("log_path"));
        } else {
            throw new IllegalArgumentException("Config must have 'log_paths' (array) or 'log_path'");
        }
        for (String p : logPaths) {
            if (!new File(p).exists()) log.warn("Log file does not exist yet (will wait): {}", p);
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

        return new CaptureConfig(logPaths, outputDir, errorStrings, ipFilters, portFilterList,
                captureMode, iface, maxTime, countLimit, finalDuration, webhookUrl);
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

                            if (line.toLowerCase().contains("error")) {
                                totalErrorsFound.incrementAndGet();
                                log.warn("[{}] Error: {}", logFilePath, line);
                            }

                            for (String err : errorStrings) {
                                if (err != null && !err.trim().isEmpty() &&
                                        line.toLowerCase().contains(err.trim().toLowerCase())) {
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
        // Rolling window: only tracks files eligible for deletion
        LinkedList<File> rollingFiles = new LinkedList<>();
        List<Process> activeProcesses = new ArrayList<>();
        boolean errorOccurred = false;

        File dir = new File(tcpDumpDir);
        if (!dir.exists()) dir.mkdirs();

        try {
            while (true) {
                if (mainErrorFound.get()) {
                    log.info("Error detected before next capture cycle — breaking.");
                    errorOccurred = true;
                    break;
                }

                File captureFile = newCaptureFile(tcpDumpDir, "tcpdump");
                Process proc;
                try {
                    proc = spawnTcpDump(ipFilters, captureFile);
                } catch (IOException e) {
                    log.error("Failed to launch tcpdump: {}", e.getMessage());
                    break;
                }

                // Brief pause then verify the process is still alive
                Thread.sleep(500);
                if (!proc.isAlive()) {
                    log.error("tcpdump exited immediately (exit={}). Check binary path and CAP_NET_RAW permission.",
                            proc.exitValue());
                    break;
                }

                activeProcesses.add(proc);
                processRegistry.add(proc);
                rollingFiles.add(captureFile);
                log.info("Capture started: {}", captureFile.getAbsolutePath());

                long startTime = System.currentTimeMillis();
                while (true) {
                    if (mainErrorFound.get()) {
                        log.info("Error detected mid-capture. Stopping: {}", captureFile.getName());
                        proc.destroy();
                        proc.waitFor(5, TimeUnit.SECONDS);
                        errorOccurred = true;
                        break;
                    }
                    if (System.currentTimeMillis() - startTime >= maxTimeThreshold) {
                        log.info("Capture window elapsed: {}", captureFile.getName());
                        proc.destroy();
                        proc.waitFor(5, TimeUnit.SECONDS);
                        break;
                    }
                    Thread.sleep(100);
                }

                if (errorOccurred) break;

                // Delete oldest rolling file only while no error has been seen —
                // once an error fires we keep all captures for forensic use
                if (rollingFiles.size() > tcpDumpCountLimit) {
                    File oldest = rollingFiles.poll();
                    if (oldest != null && oldest.exists() && oldest.delete()) {
                        log.info("Pruned old capture: {}", oldest.getName());
                    }
                }
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

        // Kill all child processes on JVM exit (SIGTERM, Ctrl+C, etc.)
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutdown hook: terminating {} tcpdump process(es).", processRegistry.size());
            for (Process p : processRegistry) {
                if (p.isAlive()) p.destroy();
            }
        }, "shutdown-hook"));

        log.info("TCPMonitor starting.");
        log.info("Log files ({}): {}", config.logPaths.size(), config.logPaths);
        log.info("Output dir  : {}", config.outputDir);
        log.info("Error triggers: {}", config.errorStrings);
        log.info("IP filters  : {} | Port filters: {} | Mode: {}",
                config.ipFilters, config.portFilters, config.captureMode);
        log.info("Capture window: {} ms | Rolling limit: {} | Final duration: {} ms",
                config.maxTimeThreshold, config.tcpDumpCountLimit, config.finalCaptureDuration);

        // One monitor thread per log file + one tcpdump manager
        ExecutorService executor = Executors.newFixedThreadPool(config.logPaths.size() + 1);

        for (String logPath : config.logPaths) {
            final String path = logPath;
            executor.submit(() -> monitorLogFile(path, config.errorStrings));
        }
        executor.submit(() -> startTcpDump(config.outputDir, config.ipFilters));

        executor.shutdown();
        try {
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        log.info("Program terminated — lines read: {} | errors found: {}",
                totalLinesRead.get(), totalErrorsFound.get());
    }
}
