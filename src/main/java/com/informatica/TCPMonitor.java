package com.informatica;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONObject;

public class TCPMonitor {
    private static final AtomicBoolean stopProgram = new AtomicBoolean(false);

    private static final AtomicBoolean mainErrorFound = new AtomicBoolean(false);

    private static int tcpDumpCountLimit;

    private static long maxTimeThreshold;

    private static int totalLinesRead = 0;

    private static int totalErrorsFound = 0;

    private static String captureInterface;

    private static CaptureMode currentCaptureMode;

    private enum CaptureMode {
        BETWEEN_IPS, ALL_TRAFFIC_FOR_IPS
    }

    public static void monitorLogFile(String logFilePath, String errorString) {
        try (BufferedReader logReader = new BufferedReader(new FileReader(logFilePath))) {
            logReader.skip((new File(logFilePath)).length());
            while (!stopProgram.get()) {
                String line;
                while ((line = logReader.readLine()) != null) {
                    totalLinesRead++;
                    if (line.toLowerCase().contains("error")) {
                        totalErrorsFound++;
                        System.out.println("Error captured: " + line);
                    }
                    if (line.contains(errorString)) {
                        System.out.println("Main Error Captured: " + line);
                        mainErrorFound.set(true);
                        stopProgram.set(true);
                        return;
                    }
                }
                Thread.sleep(100L);
            }
        } catch (Exception e) {
            System.err.println("Error monitoring log file: " + e.getMessage());
        }
    }

    private static void startTcpDump(String tcpDumpDir, List<String> ipFilters) {
        int tcpDumpCount = 0;
        List<Process> tcpDumpProcesses = new ArrayList<>();
        File tcpDumpDirFile = new File(tcpDumpDir);
        if (!tcpDumpDirFile.exists())
            tcpDumpDirFile.mkdirs();
        Thread finalTcpDumpThread = null;
        try {
            while (!stopProgram.get()) {
                String tcpDumpFileName = String.format("tcpdump_%d.pcap", Integer.valueOf(tcpDumpCount + 1));
                File tcpDumpFile = new File(tcpDumpDir, tcpDumpFileName);
                Process tcpDumpProcess = getProcess(ipFilters, tcpDumpFile, currentCaptureMode, captureInterface);
                tcpDumpProcesses.add(tcpDumpProcess);
                System.out.println("Started tcpdump: " + tcpDumpFile.getAbsolutePath());
                long startTime = System.currentTimeMillis();
                while (true) {
                    long elapsedTime = System.currentTimeMillis() - startTime;
                    if (elapsedTime >= maxTimeThreshold) {
                        System.out.println("Time limit reached for: " + tcpDumpFile.getAbsolutePath());
                        tcpDumpProcess.destroy();
                        tcpDumpProcess.waitFor(5L, TimeUnit.SECONDS);
                        break;
                    }
                    if (mainErrorFound.get()) {
                        System.out.println("Main error detected. Stopping all further TCP dumps.");
                        finalTcpDumpThread = new Thread(() -> {
                            try {
                                String finalCaptureFileName = "tcpdump_final_capture.pcap";
                                File finalCaptureFile = new File(tcpDumpDir, finalCaptureFileName);
                                System.out.println("Starting final tcpdump capture: " + finalCaptureFile.getAbsolutePath());
                                List<String> finalCommand = new ArrayList<>();
                                finalCommand.add("tcpdump");
                                if (captureInterface != null && !captureInterface.isEmpty()) {
                                    finalCommand.add("-i");
                                    finalCommand.add(captureInterface);
                                }
                                finalCommand.add("-s");
                                finalCommand.add("0");
                                finalCommand.add("-w");
                                finalCommand.add(finalCaptureFile.getAbsolutePath());
                                if (!ipFilters.isEmpty() && currentCaptureMode == CaptureMode.BETWEEN_IPS) {
                                    if (ipFilters.size() >= 2) {
                                        finalCommand.add("host");
                                        finalCommand.add(ipFilters.get(0));
                                        finalCommand.add("and");
                                        finalCommand.add("host");
                                        finalCommand.add(ipFilters.get(1));
                                    } else {
                                        System.err.println("Warning: 'between_ips' mode requires at least two IP addresses for final capture. Capturing all traffic for specified IPs.");
                                        for (String ip : ipFilters) {
                                            finalCommand.add("host");
                                            finalCommand.add(ip);
                                            finalCommand.add("or");
                                        }
                                        if (!ipFilters.isEmpty())
                                            finalCommand.remove(finalCommand.size() - 1);
                                    }
                                } else if (!ipFilters.isEmpty()) {
                                    for (String ip : ipFilters) {
                                        finalCommand.add("host");
                                        finalCommand.add(ip);
                                        finalCommand.add("or");
                                    }
                                    finalCommand.remove(finalCommand.size() - 1);
                                }
                                ProcessBuilder finalProcessBuilder = new ProcessBuilder(finalCommand);
                                System.out.println("Executing final tcpdump command: " + String.join(" ", (Iterable)finalCommand));
                                Process finalTcpDumpProcess = finalProcessBuilder.start();
                                Thread.sleep(120000L);
                                finalTcpDumpProcess.destroy();
                                finalTcpDumpProcess.waitFor(5L, TimeUnit.SECONDS);
                                System.out.println("Final tcpdump capture completed.");
                            } catch (Exception e) {
                                System.err.println("Error in final tcpdump thread: " + e.getMessage());
                            }
                        });
                        finalTcpDumpThread.start();
                        Thread.sleep(120000L);
                        stopProgram.set(true);
                        tcpDumpProcess.destroy();
                        tcpDumpProcess.waitFor(5L, TimeUnit.SECONDS);
                        break;
                    }
                }
                tcpDumpCount++;
                if (tcpDumpCount > tcpDumpCountLimit) {
                    File oldestFile = new File(tcpDumpDir, String.format("tcpdump_%d.pcap", new Object[] { Integer.valueOf(tcpDumpCount - tcpDumpCountLimit) }));
                    if (oldestFile.exists()) {
                        if (oldestFile.delete()) {
                            System.out.println("Deleted oldest TCP dump file: " + oldestFile.getAbsolutePath());
                            continue;
                        }
                        System.err.println("Failed to delete oldest TCP dump file: " + oldestFile.getAbsolutePath());
                    }
                }
            }
            if (finalTcpDumpThread != null)
                finalTcpDumpThread.join();
        } catch (Exception e) {
            System.err.println("Error in TCP dump monitoring: " + e.getMessage());
        } finally {
            for (Process process : tcpDumpProcesses)
                process.destroy();
        }
        System.out.println("All TCP dumps have stopped. Exiting program.");
    }

    private static Process getProcess(List<String> ipFilters, File tcpDumpFile, CaptureMode mode, String captureInterface) throws IOException {
        List<String> command = new ArrayList<>();
        command.add("tcpdump");
        if (captureInterface != null && !captureInterface.isEmpty()) {
            command.add("-i");
            command.add(captureInterface);
        }
        command.add("-s");
        command.add("0");
        command.add("-w");
        command.add(tcpDumpFile.getAbsolutePath());
        if (ipFilters != null && !ipFilters.isEmpty())
            if (mode == CaptureMode.BETWEEN_IPS) {
                if (ipFilters.size() >= 2) {
                    command.add("host");
                    command.add(ipFilters.get(0));
                    command.add("and");
                    command.add("host");
                    command.add(ipFilters.get(1));
                } else {
                    System.err.println("Warning: 'between_ips' mode requires at least two IP addresses. Falling back to 'all_traffic_for_ips' for provided IPs.");
                    for (String ip : ipFilters) {
                        command.add("host");
                        command.add(ip);
                        command.add("or");
                    }
                    if (!ipFilters.isEmpty())
                        command.remove(command.size() - 1);
                }
            } else {
                for (String ip : ipFilters) {
                    command.add("host");
                    command.add(ip);
                    command.add("or");
                }
                command.remove(command.size() - 1);
            }
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        System.out.println("Executing tcpdump command: " + String.join(" ", (Iterable)command));
        return processBuilder.start();
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Please provide the path to the config.json file as an argument.");
            return;
        }
        String configFilePath = args[0];
        File configFile = new File(configFilePath);
        if (!configFile.exists()) {
            System.out.println("Configuration file not found: " + configFilePath);
            return;
        }
        try {
            String configContent = new String(Files.readAllBytes(configFile.toPath()));
            JSONObject config = new JSONObject(configContent);
            String logPath = config.getString("log_path");
            String errorString = config.optString("error_string", "Tunnel connection error: 307");
            String tcpdumpOutputDir = config.getString("tcpdump_output_dir");
            maxTimeThreshold = config.optLong("max_time_threshold", 30000L);
            tcpDumpCountLimit = config.optInt("tcp_dump_count", 5);
            JSONArray ipFilterArray = config.optJSONArray("ip_filters");
            List<String> ipFilters = new ArrayList<>();
            if (ipFilterArray != null)
                for (int i = 0; i < ipFilterArray.length(); i++)
                    ipFilters.add(ipFilterArray.getString(i));
            String captureModeStr = config.optString("capture_mode", "all_traffic_for_ips");
            try {
                currentCaptureMode = CaptureMode.valueOf(captureModeStr.toUpperCase());
            } catch (IllegalArgumentException e) {
                System.err.println("Invalid 'capture_mode' specified in config: " + captureModeStr + ". Using default 'all_traffic_for_ips'.");
                currentCaptureMode = CaptureMode.ALL_TRAFFIC_FOR_IPS;
            }
            captureInterface = config.optString("interface", "");
            File logFile = new File(logPath);
            if (!logFile.exists()) {
                System.out.println("Log not found in the path: " + logPath);
                return;
            }
            File outputDir = new File(tcpdumpOutputDir);
            if (!outputDir.exists()) {
                System.out.println("TCP dump output directory does not exist. Creating: " + tcpdumpOutputDir);
                outputDir.mkdirs();
            } else if (!outputDir.isDirectory()) {
                System.out.println("TCP dump output directory is not a directory: " + tcpdumpOutputDir);
                return;
            }
            ExecutorService executor = Executors.newFixedThreadPool(2);
            executor.submit(() -> monitorLogFile(logFile.getAbsolutePath(), errorString));
            executor.submit(() -> startTcpDump(tcpdumpOutputDir, ipFilters));
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("Exiting...");
                stopProgram.set(true);
            }));
            executor.shutdown();
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.MILLISECONDS);
            System.out.println("Program terminated.");
            System.out.println("Lines read: " + totalLinesRead);
            System.out.println("Errors captured: " + totalErrorsFound);
            System.out.println("Output directory: " + tcpdumpOutputDir);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
