package cyberforge.cli;

import cyberforge.analysis.Finding;
import cyberforge.analysis.StaticAnalyzer;
import cyberforge.evidence.EvidenceManager;
import cyberforge.model.Target;
import cyberforge.util.SecurityLimits;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/**
 * Implements the behaviour of each CyberForge CLI command.
 *
 * SECURITY MODEL:
 *  - Every command argument that reaches this class is validated (length,
 *    control characters) before being used for anything, even though
 *    TargetLoader independently re-validates too — defense in depth means a
 *    single validation bug in one layer doesn't become an exploitable path.
 *  - Failures are always reported with a SHORT, SAFE message. Raw exceptions
 *    (and their stack traces, which can embed absolute filesystem paths or
 *    other environment details) are never printed directly to the operator;
 *    see handleUnexpected() below.
 *
 * BUILD STATUS (Priority 1-3 of the master spec):
 *  - `help`, `status`, `scan`      — fully real, end-to-end.
 *  - `analyze`                     — real target loading + real Semgrep
 *                                     static analysis + real evidence JSON
 *                                     written to disk. Dynamic analysis,
 *                                     fuzzing, AI reasoning, and patching
 *                                     (Priorities 4-11) are NOT implemented
 *                                     yet and are reported as such — never
 *                                     faked.
 *  - `repair`, `verify`            — still stubs; depend on Priorities 4-8.
 */
public class CommandHandler {

    /** Local, offline semgrep ruleset — never `--config=auto` (registry/network). */
    private static final Path RULES_FILE = Path.of("rules", "basic-security.yml");
    private static final Path EVIDENCE_DIR = Path.of("evidence");

    private final SystemChecker systemChecker = new SystemChecker();
    private final TargetLoader targetLoader = new TargetLoader();
    private final StaticAnalyzer staticAnalyzer = new StaticAnalyzer(RULES_FILE);
    private final EvidenceManager evidenceManager = new EvidenceManager(EVIDENCE_DIR);

    public void help() {
        System.out.println("Available commands:");
        System.out.println("  help              Show this help message");
        System.out.println("  status            Re-check security tools and AI engine availability");
        System.out.println("  scan <path>       Load a target project and summarize its contents");
        System.out.println("  analyze <path>    Load target + run real static analysis + write evidence");
        System.out.println("  repair <path>     Generate and apply a patch for a previously analyzed target");
        System.out.println("  verify <path>     Re-run tests to verify a previously applied patch");
        System.out.println("  exit              Exit CyberForge");
    }

    public void status() {
        System.out.println("[+] Checking security tools");
        printCheck("    +- Semgrep", systemChecker.checkSemgrep());
        printCheck("    +- Docker ", systemChecker.checkDocker());
        printCheck("    `- Rust   ", systemChecker.checkRustc());
        System.out.println();
        System.out.println("[+] Checking AI engine");
        printCheck("    +- Ollama      ", systemChecker.checkOllama());
        printCheck("    `- Local Model ", systemChecker.checkOllamaModel(SystemChecker.REQUIRED_OLLAMA_MODEL));
    }

    public void scan(String path) {
        if (!validateArg("scan", path)) {
            return;
        }
        try {
            Target target = targetLoader.load(path);
            System.out.println("[1/1] Loading target.......................... " + tick(true));
            System.out.println();
            printTargetSummary(target);
        } catch (IOException e) {
            // IOExceptions thrown by TargetLoader always carry a short, safe,
            // pre-composed message (never a raw stack trace) — see TargetLoader's
            // SECURITY MODEL doc. Safe to print directly.
            System.out.println("[!] Failed to load target: " + e.getMessage());
        } catch (RuntimeException e) {
            handleUnexpected("scan", e);
        }
    }

    public void analyze(String path) {
        if (!validateArg("analyze", path)) {
            return;
        }
        try {
            // ---- [1/7] Load target (real) ----
            Target target = targetLoader.load(path);
            System.out.println("[1/7] Loading target........................... " + tick(true));
            System.out.println("      Files discovered: " + target.getFileCount()
                    + " (" + target.getPrimaryLanguage() + ")");

            // ---- [2/7] Static analysis (real) ----
            SystemChecker.ToolStatus semgrepStatus = systemChecker.checkSemgrep();
            if (!semgrepStatus.available()) {
                System.out.println("[2/7] Running static analysis.................. " + tick(false));
                System.out.println("[!] Semgrep is not available (" + semgrepStatus.detail()
                        + "). Install it (`pip install semgrep`) to run static analysis.");
                printPipelinePendingNotice();
                return;
            }

            StaticAnalyzer.AnalysisResult analysis = staticAnalyzer.analyze(target.getPath());
            System.out.println("[2/7] Running static analysis.................. " + tick(analysis.succeeded));
            if (!analysis.succeeded) {
                System.out.println("[!] Static analysis failed: " + analysis.errorMessage);
                printPipelinePendingNotice();
                return;
            }

            // ---- [3/7], [4/7] Dynamic analysis / fuzzing — honestly not implemented ----
            System.out.println("[3/7] Running dynamic analysis................. (not implemented - Priority 11)");
            System.out.println("[4/7] Running fuzzing........................... (not implemented - Priority 10)");

            // ---- [5/7] Evidence collection (real) ----
            Path evidenceFile;
            try {
                evidenceFile = evidenceManager.writeEvidence(target.getPath(), target.getPrimaryLanguage(),
                        target.getFileCount(), analysis.findings, true, null);
            } catch (IOException e) {
                System.out.println("[5/7] Collecting security evidence.............. " + tick(false));
                System.out.println("[!] Failed to write evidence: " + e.getMessage());
                printPipelinePendingNotice();
                return;
            }
            System.out.println("[5/7] Collecting security evidence.............. " + tick(true));
            System.out.println("      Evidence written to: " + evidenceFile);

            System.out.println();
            printFindings(analysis.findings);

            // ---- [6/7], [7/7] Reasoning / remediation — honestly not implemented ----
            System.out.println();
            System.out.println("[6/7] Cyber reasoning........................... (not implemented - Priority 4-5, local LLM)");
            System.out.println("[7/7] Generating remediation..................... (not implemented - Priority 6)");
            System.out.println();
            System.out.println("[+] Static analysis is real and complete; evidence has been written to disk.");
            System.out.println("    The AI reasoning/patch/verification loop (Priorities 4-8) is not wired");
            System.out.println("    in yet, so no vulnerability explanation or patch is generated here —");
            System.out.println("    CyberForge never fabricates that output.");
        } catch (IOException e) {
            System.out.println("[!] Failed to load target: " + e.getMessage());
        } catch (RuntimeException e) {
            handleUnexpected("analyze", e);
        }
    }

    public void repair(String path) {
        System.out.println("[!] 'repair' depends on evidence + reasoning output from 'analyze',");
        System.out.println("    which is not implemented yet (Priorities 4-6). Nothing to repair.");
    }

    public void verify(String path) {
        System.out.println("[!] 'verify' depends on a previously applied patch, which requires");
        System.out.println("    'repair' to exist first (Priorities 6-8). Not implemented yet.");
    }

    // -----------------------------------------------------------------
    // Output helpers
    // -----------------------------------------------------------------

    private void printTargetSummary(Target target) {
        System.out.println("Target path        : " + target.getPath());
        System.out.println("Files discovered    : " + target.getFileCount());
        System.out.println("Primary language    : " + target.getPrimaryLanguage());
        System.out.println("Total size           : " + target.getTotalSizeBytes() + " bytes");

        if (target.isLimitReached()) {
            System.out.println();
            System.out.println("[!] A resource limit was reached while walking this target");
            System.out.println("    (see SecurityLimits) — this is a partial view, not a");
            System.out.println("    complete inventory of the target.");
        }

        if (!target.getSkippedEntries().isEmpty()) {
            System.out.println();
            System.out.println("Skipped entries (security-relevant — symlinks are never followed,");
            System.out.println("special files are never read):");
            target.getSkippedEntries().stream().limit(20)
                    .forEach(s -> System.out.println("  - " + s));
            if (target.getSkippedEntries().size() > 20) {
                System.out.println("  ... and " + (target.getSkippedEntries().size() - 20) + " more");
            }
        }

        if (target.getFileCount() > 0) {
            System.out.println();
            System.out.println("Files:");
            target.getSourceFiles().stream().limit(50)
                    .forEach(f -> System.out.println("  - " + f));
            if (target.getFileCount() > 50) {
                System.out.println("  ... and " + (target.getFileCount() - 50) + " more");
            }
        } else {
            System.out.println();
            System.out.println("[!] No files found at this path.");
        }
    }

    private void printFindings(List<Finding> findings) {
        if (findings.isEmpty()) {
            System.out.println("No findings from the local ruleset.");
            return;
        }
        System.out.println(findings.size() + " finding(s):");
        for (Finding f : findings) {
            System.out.println();
            System.out.println("  Rule       : " + f.ruleId());
            System.out.println("  Severity   : " + f.severity());
            System.out.println("  Location   : " + f.filePath() + ":" + f.startLine() + "-" + f.endLine());
            System.out.println("  Message    : " + f.message());
        }
    }

    private void printPipelinePendingNotice() {
        System.out.println();
        System.out.println("[!] The remaining pipeline stages (dynamic analysis, fuzzing, AI");
        System.out.println("    reasoning, patch generation, testing, verification) are not");
        System.out.println("    implemented yet (Priorities 4-11).");
    }

    /**
     * Validates a path-like argument before it is used for anything. This
     * duplicates part of what TargetLoader itself checks — intentionally: two
     * independent validation layers mean a bug in either one alone can't open a
     * hole, and the error message here is friendlier/faster for the common case
     * of a missing argument.
     */
    private boolean validateArg(String commandName, String arg) {
        if (arg == null || arg.isBlank()) {
            System.out.println("[!] Usage: " + commandName + " <path>");
            return false;
        }
        if (arg.length() > SecurityLimits.MAX_PATH_ARG_LENGTH) {
            System.out.println("[!] Argument exceeds maximum accepted length ("
                    + SecurityLimits.MAX_PATH_ARG_LENGTH + " chars)");
            return false;
        }
        for (int i = 0; i < arg.length(); i++) {
            char c = arg.charAt(i);
            if (c == '\0' || Character.isISOControl(c)) {
                System.out.println("[!] Argument contains an illegal control character");
                return false;
            }
        }
        return true;
    }

    /**
     * Central handler for any unexpected RuntimeException reaching this layer.
     * Deliberately prints only the exception's class name — never getMessage()
     * or a stack trace — to the operator, since those can embed absolute paths,
     * environment details, or other internals that shouldn't be surfaced
     * casually. Availability is preserved: the command fails cleanly instead of
     * crashing the whole CLI/REPL.
     */
    private void handleUnexpected(String commandName, RuntimeException e) {
        System.out.println("[!] '" + commandName + "' failed unexpectedly (" + e.getClass().getSimpleName() + ")");
    }

    private void printCheck(String label, SystemChecker.ToolStatus status) {
        String mark = tick(status.available());
        String detail = status.detail() == null || status.detail().isBlank() ? "" : " (" + status.detail() + ")";
        System.out.println(label + "............ " + mark + detail);
    }

    private String tick(boolean ok) {
        return ok ? "\u2713" : "\u2717";
    }
}
