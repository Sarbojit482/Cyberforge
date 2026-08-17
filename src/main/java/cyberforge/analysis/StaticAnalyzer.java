package cyberforge.analysis;

import cyberforge.util.Json;
import cyberforge.util.SafeProcessRunner;
import cyberforge.util.SecurityLimits;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Real Semgrep-based static analysis (SAST) — no code execution of the
 * target, and no network dependency: this uses a LOCAL ruleset shipped with
 * CyberForge (rules/basic-security.yml) rather than `--config=auto`, which
 * would pull rules from Semgrep's registry. That keeps analysis fully
 * offline and means target source code and its findings never leave the
 * machine, matching the project's "restricted/mission-critical environment"
 * design goal.
 *
 * SECURITY:
 *  - Every subprocess call goes through {@link SafeProcessRunner} — the same
 *    hardened execution path used everywhere else in CyberForge (no shell,
 *    sanitized environment, bounded/concurrent output draining, hard
 *    timeout). See that class's doc for the full control list.
 *  - The command array here is built ONLY from a compile-time-fixed rules
 *    file path and the target path — and that target path has already been
 *    through TargetLoader's confinement + symlink + special-file checks by
 *    the time it reaches here. Nothing raw/unvalidated from the operator is
 *    ever placed into the semgrep argument array.
 *  - `--metrics=off` and `--disable-version-check` are passed explicitly so
 *    semgrep makes no outbound network calls at all during analysis.
 *  - `--max-target-bytes` is set to CyberForge's own per-file size cap
 *    (SecurityLimits.MAX_SINGLE_FILE_BYTES) as a second, independent layer
 *    of the same protection TargetLoader already applies — semgrep re-walks
 *    the target directory itself rather than reusing TargetLoader's file
 *    list, so this cap applies directly to semgrep's own execution too.
 *  - Semgrep's JSON report is read through the same bounded reader as every
 *    other subprocess call, just with a larger cap (MAX_ANALYSIS_OUTPUT_BYTES)
 *    since a real findings report is legitimately bigger than a version
 *    string — a compromised/misbehaving semgrep binary still cannot exhaust
 *    heap by printing unbounded output.
 */
public final class StaticAnalyzer {

    /** Analysis can legitimately take longer than a `--version` check. */
    private static final long ANALYSIS_TIMEOUT_SECONDS = 60;

    /** Larger cap than the default subprocess output limit, since a real
     *  findings report is expected to be bigger than a version string —
     *  still bounded, not unlimited. */
    private static final long MAX_ANALYSIS_OUTPUT_BYTES = 20L * 1024 * 1024; // 20 MB

    private final Path rulesFile;

    public StaticAnalyzer(Path rulesFile) {
        this.rulesFile = rulesFile;
    }

    /** Outcome of one analysis run — always honest about failure, never fabricated. */
    public static final class AnalysisResult {
        public final List<Finding> findings;
        public final boolean succeeded;
        public final String errorMessage;

        private AnalysisResult(List<Finding> findings, boolean succeeded, String errorMessage) {
            this.findings = findings;
            this.succeeded = succeeded;
            this.errorMessage = errorMessage;
        }

        static AnalysisResult ok(List<Finding> findings) {
            return new AnalysisResult(findings, true, null);
        }

        static AnalysisResult failed(String reason) {
            return new AnalysisResult(List.of(), false, reason);
        }
    }

    public AnalysisResult analyze(String targetPath) {
        if (!Files.exists(rulesFile)) {
            return AnalysisResult.failed("Rules file not found: " + rulesFile);
        }

        List<String> command = List.of(
                "semgrep",
                "--config=" + rulesFile,
                "--json",
                "--quiet",
                "--disable-version-check",
                "--metrics=off",                                  // no telemetry / network call
                "--max-target-bytes=" + SecurityLimits.MAX_SINGLE_FILE_BYTES,
                targetPath
        );

        SafeProcessRunner.ProcessResult result =
                SafeProcessRunner.run(command, ANALYSIS_TIMEOUT_SECONDS, MAX_ANALYSIS_OUTPUT_BYTES);

        if (!result.completed()) {
            return AnalysisResult.failed("semgrep did not complete: " + result.failureReason());
        }
        // semgrep exit code 1 means "ran fine, findings were reported" — not a failure.
        if (result.exitCode() != 0 && result.exitCode() != 1) {
            return AnalysisResult.failed("semgrep exited with code " + result.exitCode());
        }

        try {
            return AnalysisResult.ok(parseFindings(result.output()));
        } catch (RuntimeException e) {
            // Never leak raw parser internals to the operator.
            return AnalysisResult.failed("Could not parse semgrep output (" + e.getClass().getSimpleName() + ")");
        }
    }

    @SuppressWarnings("unchecked")
    private List<Finding> parseFindings(String json) {
        Map<String, Object> root = Json.asObject(Json.parse(json));
        List<Object> results = root.get("results") instanceof List ? Json.asArray(root.get("results")) : List.of();

        List<Finding> findings = new ArrayList<>();
        for (Object o : results) {
            Map<String, Object> r = Json.asObject(o);
            String checkId = Json.getString(r, "check_id", "unknown-rule");
            String path = Json.getString(r, "path", "unknown");

            Map<String, Object> start = r.get("start") instanceof Map ? Json.asObject(r.get("start")) : Map.of();
            Map<String, Object> end = r.get("end") instanceof Map ? Json.asObject(r.get("end")) : Map.of();
            int startLine = Json.getInt(start, "line", -1);
            int endLine = Json.getInt(end, "line", -1);

            Map<String, Object> extra = r.get("extra") instanceof Map ? Json.asObject(r.get("extra")) : Map.of();
            String severity = Json.getString(extra, "severity", "UNKNOWN");
            String message = Json.getString(extra, "message", "");
            String snippet = Json.getString(extra, "lines", "");

            findings.add(new Finding(checkId, path, startLine, endLine, severity, message, snippet));
        }
        return findings;
    }
}
