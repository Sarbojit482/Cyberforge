package cyberforge.cli;

import cyberforge.util.SafeProcessRunner;
import cyberforge.util.SecurityLimits;

import java.util.List;
import java.util.Locale;

/**
 * Performs REAL environment checks by invoking external tool binaries
 * (semgrep, docker, ollama, rustc) — never simulated.
 *
 * All subprocess execution is delegated to {@link SafeProcessRunner}, which
 * is the single hardened implementation shared by every part of CyberForge
 * that shells out (see that class's SECURITY MODEL doc for the six controls
 * enforced on every invocation: no shell, no user-controlled command
 * construction, sanitized environment, closed stdin, bounded/concurrent
 * output draining, hard timeout).
 */
public final class SystemChecker {

    /** Result of checking a single external dependency. */
    public record ToolStatus(String name, boolean available, String detail) {
    }

    /** Name of the Ollama model CyberForge expects to use as its reasoning engine. */
    public static final String REQUIRED_OLLAMA_MODEL = "qwen2.5-coder:7b";

    public ToolStatus checkSemgrep() {
        return runVersionCheck("Semgrep", "semgrep", "--version");
    }

    public ToolStatus checkDocker() {
        return runVersionCheck("Docker", "docker", "--version");
    }

    public ToolStatus checkOllama() {
        return runVersionCheck("Ollama", "ollama", "--version");
    }

    public ToolStatus checkRustc() {
        return runVersionCheck("Rust (rustc)", "rustc", "--version");
    }

    /**
     * Checks that a specific model is present in the local Ollama model store by
     * actually running `ollama list` and searching its (bounded) output.
     */
    public ToolStatus checkOllamaModel(String modelName) {
        if (modelName == null || modelName.isBlank() || modelName.length() > 256) {
            return new ToolStatus("model", false, "invalid model name");
        }

        ToolStatus ollama = checkOllama();
        if (!ollama.available()) {
            return new ToolStatus(modelName, false, "Ollama is not installed/running");
        }

        SafeProcessRunner.ProcessResult result = SafeProcessRunner.run(
                List.of("ollama", "list"),
                SecurityLimits.PROCESS_TIMEOUT_SECONDS,
                SecurityLimits.MAX_PROCESS_OUTPUT_BYTES);

        if (!result.completed()) {
            return new ToolStatus(modelName, false, result.failureReason());
        }
        String needle = modelName.toLowerCase(Locale.ROOT).split(":")[0];
        boolean found = result.output().toLowerCase(Locale.ROOT).contains(needle);
        return new ToolStatus(modelName, found,
                found ? "model present" : "model not pulled (run: ollama pull " + modelName + ")");
    }

    /**
     * Runs `<command...>` and reports success/version string. The command array
     * is always a compile-time constant supplied by the caller.
     */
    private ToolStatus runVersionCheck(String displayName, String... command) {
        SafeProcessRunner.ProcessResult result = SafeProcessRunner.run(
                List.of(command),
                SecurityLimits.PROCESS_TIMEOUT_SECONDS,
                SecurityLimits.MAX_PROCESS_OUTPUT_BYTES);

        if (!result.completed()) {
            return new ToolStatus(displayName, false, result.failureReason());
        }
        if (result.exitCode() != 0) {
            return new ToolStatus(displayName, false, "exit code " + result.exitCode());
        }
        String output = result.output();
        String firstLine = output.isBlank() ? "" : output.strip().split("\\R")[0];
        return new ToolStatus(displayName, true, firstLine);
    }
}
