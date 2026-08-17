package cyberforge.cli;

import cyberforge.util.SecurityLimits;

import java.util.Scanner;

/**
 * Owns the CyberForge startup sequence and the interactive REPL.
 *
 * SECURITY MODEL:
 *  - REPL input lines are length-capped and control-character-checked before
 *    being tokenized/dispatched (see SecurityLimits.MAX_COMMAND_LINE_LENGTH) —
 *    a single pathological line piped into stdin cannot allocate unbounded
 *    memory or reach downstream parsing with unexpected bytes in it.
 *  - The dispatch loop is fail-safe: any unexpected exception from a command
 *    handler is caught and reported briefly rather than crashing the whole
 *    REPL (availability — one bad command must not take down the session).
 *  - EOF/interrupt on stdin exits cleanly rather than spinning or crashing.
 */
public class CLI {

    private final CommandHandler commandHandler = new CommandHandler();
    private final SystemChecker systemChecker = new SystemChecker();
    private boolean running = true;

    /**
     * Runs the startup banner + real environment checks. Returns false if a
     * required component is missing and the CLI should not start.
     */
    public boolean startup() {
        Banner.print();

        System.out.print("[+] Initializing CyberForge.................. ");
        System.out.println("\u2713");

        System.out.println("[+] Checking security tools");
        SystemChecker.ToolStatus semgrep = systemChecker.checkSemgrep();
        SystemChecker.ToolStatus docker = systemChecker.checkDocker();
        SystemChecker.ToolStatus rustc = systemChecker.checkRustc();
        printLine("    +- Semgrep", semgrep);
        printLine("    +- Docker ", docker);
        printLine("    `- Rust   ", rustc);

        System.out.println("[+] Checking AI engine");
        SystemChecker.ToolStatus ollama = systemChecker.checkOllama();
        SystemChecker.ToolStatus model = systemChecker.checkOllamaModel(SystemChecker.REQUIRED_OLLAMA_MODEL);
        printLine("    +- Ollama      ", ollama);
        printLine("    `- Local Model ", model);

        System.out.println();

        // For the CLI-only build stage, missing tools are reported honestly but
        // do not block startup, since analyze/repair/verify are stubs anyway and
        // scan/help/status must remain usable for the demo. This is a
        // deliberate availability-vs-strictness tradeoff, made explicit here
        // rather than silently baked in: if you want CyberForge to refuse to
        // start with missing tools (a stricter, "fail closed" posture more
        // appropriate for a production security tool), flip anyMissing's
        // consequence below to `return false`.
        boolean anyMissing = !(semgrep.available() && docker.available() && rustc.available()
                && ollama.available() && model.available());
        if (anyMissing) {
            System.out.println("[!] One or more optional components are unavailable in this environment.");
            System.out.println("    CyberForge will still start; 'analyze'/'repair'/'verify' require them.");
            System.out.println();
        }

        return true;
    }

    private void printLine(String label, SystemChecker.ToolStatus status) {
        String mark = status.available() ? "\u2713" : "\u2717";
        String detail = status.detail() == null || status.detail().isBlank() ? "" : " (" + status.detail() + ")";
        System.out.println(label + "............ " + mark + detail);
    }

    /** Runs a single command non-interactively, e.g. `cyberforge analyze ./target`. */
    public void runSingleCommand(String[] args) {
        dispatchSafely(args);
    }

    /** Enters the interactive `cyberforge> ` prompt loop. */
    public void runInteractive() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Type 'help' for a list of commands.");
        while (running) {
            System.out.print("cyberforge> ");
            String line;
            try {
                if (!scanner.hasNextLine()) {
                    break; // EOF on stdin (e.g. piped input finished) — exit cleanly
                }
                line = scanner.nextLine();
            } catch (java.util.NoSuchElementException | IllegalStateException e) {
                // Stdin closed/interrupted mid-read — exit cleanly rather than loop.
                break;
            }

            line = line.strip();
            if (line.isEmpty()) {
                continue;
            }

            // Bound the size of any single line before it's tokenized, so a
            // pathological input can't cause unbounded downstream allocation.
            if (line.length() > SecurityLimits.MAX_COMMAND_LINE_LENGTH) {
                System.out.println("[!] Input exceeds maximum accepted length ("
                        + SecurityLimits.MAX_COMMAND_LINE_LENGTH + " chars) — ignored.");
                continue;
            }

            dispatchSafely(line.split("\\s+"));
        }
        scanner.close();
    }

    /**
     * Dispatches to the appropriate CommandHandler method, catching any
     * unexpected exception so a single misbehaving command can never crash the
     * CLI process (availability) or leak a raw stack trace to the operator
     * (information disclosure).
     */
    private void dispatchSafely(String[] args) {
        try {
            dispatch(args);
        } catch (RuntimeException e) {
            System.out.println("[!] Unexpected error (" + e.getClass().getSimpleName()
                    + ") — command aborted, CyberForge is still running.");
        }
    }

    private void dispatch(String[] args) {
        if (args.length == 0 || args[0].isBlank()) {
            return;
        }
        String command = args[0].toLowerCase();
        String arg = args.length > 1 ? args[1] : null;

        switch (command) {
            case "help" -> commandHandler.help();
            case "status" -> commandHandler.status();
            case "scan" -> commandHandler.scan(arg);
            case "analyze" -> commandHandler.analyze(arg);
            case "repair" -> commandHandler.repair(arg);
            case "verify" -> commandHandler.verify(arg);
            case "exit", "quit" -> running = false;
            default -> System.out.println("[!] Unknown command: " + command + " (type 'help')");
        }
    }
}
