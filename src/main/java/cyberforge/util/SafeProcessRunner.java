package cyberforge.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Single, shared, hardened subprocess runner used by EVERY part of CyberForge
 * that invokes an external binary (SystemChecker's tool-version checks,
 * StaticAnalyzer's semgrep invocation, and any future component — DAST,
 * fuzzing, regression testing, Docker sandbox control, etc.).
 *
 * Centralizing this in one class means the six security controls below are
 * implemented and audited ONCE, and every caller gets all of them for free —
 * the exact opposite of copy-pasting a "mostly safe" subprocess call into
 * each new analysis component as the project grows.
 *
 * ================================ SECURITY MODEL ================================
 *  CONTROL 1 — NO SHELL, EVER
 *      ProcessBuilder is always given a fixed argument ARRAY, never a string
 *      handed to /bin/sh -c. There is no shell to inject into.
 *
 *  CONTROL 2 — NO USER-CONTROLLED COMMAND CONSTRUCTION
 *      This class does not build commands; it only executes an array its
 *      caller supplies. Every current caller (SystemChecker, StaticAnalyzer)
 *      builds that array entirely from compile-time constants plus a
 *      confinement-checked, validated target PATH — never raw, unvalidated
 *      user input, and never string concatenation into a single argument
 *      that could smuggle extra flags or values.
 *
 *  CONTROL 3 — SANITIZED CHILD ENVIRONMENT
 *      The child does not inherit CyberForge's environment unmodified.
 *      Well-known environment-based injection/hijack vectors (LD_PRELOAD,
 *      PYTHONPATH, NODE_OPTIONS, BASH_ENV, ...) are stripped defensively.
 *
 *  CONTROL 4 — STDIN CLOSED IMMEDIATELY
 *      None of CyberForge's subprocess calls send input, so stdin is closed
 *      right after start() — a child blocking on a stdin read can never hang
 *      CyberForge.
 *
 *  CONTROL 5 — BOUNDED, CONCURRENT OUTPUT READING
 *      stdout/stderr are merged and drained on a background thread
 *      CONCURRENTLY with waitFor(), capped at a caller-supplied byte limit.
 *      Reading only after waitFor() returns is a classic Java deadlock: if
 *      the child fills its stdout pipe buffer before exiting, it blocks
 *      waiting for us to read while we block waiting for it to exit. The cap
 *      also means a misbehaving or compromised binary cannot exhaust heap by
 *      printing unbounded output (e.g. a huge/malformed JSON report).
 *
 *  CONTROL 6 — HARD TIMEOUT
 *      Every invocation is force-killed after a caller-supplied timeout if
 *      it hasn't finished, so a hung tool cannot hang CyberForge itself.
 * ===================================================================================
 */
public final class SafeProcessRunner {

    private SafeProcessRunner() {
    }

    /** Environment variables stripped from every child process — see CONTROL 3. */
    private static final Set<String> BLOCKED_ENV_VARS = Set.of(
            "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
            "PYTHONPATH", "PYTHONSTARTUP",
            "NODE_OPTIONS", "NODE_PATH",
            "PERL5LIB", "RUBYOPT",
            "BASH_ENV", "ENV", "IFS",
            "GIT_SSH_COMMAND"
    );

    /** Immutable result of a completed (or failed-to-run/timed-out) subprocess. */
    public record ProcessResult(boolean completed, int exitCode, String output, String failureReason) {
        public static ProcessResult ok(int exitCode, String output) {
            return new ProcessResult(true, exitCode, output, null);
        }

        public static ProcessResult failed(String reason) {
            return new ProcessResult(false, -1, "", reason);
        }
    }

    /**
     * Runs {@code command} (a fixed argument array — CONTROL 1/2) and returns its
     * merged, bounded stdout+stderr, honoring {@code timeoutSeconds} and
     * {@code maxOutputBytes}.
     */
    public static ProcessResult run(List<String> command, long timeoutSeconds, long maxOutputBytes) {
        ProcessBuilder builder = new ProcessBuilder(command);

        // CONTROL 3: sanitized child environment.
        Map<String, String> env = builder.environment();
        for (String blocked : BLOCKED_ENV_VARS) {
            env.remove(blocked);
        }

        builder.redirectErrorStream(true);

        Process process;
        try {
            process = builder.start();
        } catch (IOException e) {
            // Never leak raw OS/JVM exception internals — short safe reason only.
            return ProcessResult.failed("not found on PATH");
        }

        // CONTROL 4: close stdin immediately.
        try {
            process.getOutputStream().close();
        } catch (IOException ignored) {
            // Non-fatal.
        }

        // CONTROL 5: bounded, concurrent output draining.
        BoundedReader reader = new BoundedReader(process.getInputStream(), maxOutputBytes);
        Thread readerThread = new Thread(reader, "cyberforge-proc-reader");
        readerThread.setDaemon(true);
        readerThread.start();

        boolean finished;
        try {
            // CONTROL 6: hard timeout.
            finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return ProcessResult.failed("check interrupted");
        }

        if (!finished) {
            process.destroyForcibly();
            return ProcessResult.failed("timed out after " + timeoutSeconds + "s");
        }

        try {
            readerThread.join(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        int exitCode = process.exitValue();
        String output = reader.getOutput();
        if (reader.wasTruncated()) {
            output += System.lineSeparator() + "[output truncated at " + maxOutputBytes + " bytes]";
        }
        return ProcessResult.ok(exitCode, output);
    }

    /**
     * Drains an InputStream on its own thread, buffering up to {@code limit}
     * bytes and discarding (without buffering) anything beyond that, so the
     * child process's pipe is never left blocked full even once the cap is hit.
     */
    private static final class BoundedReader implements Runnable {
        private final InputStream in;
        private final long limit;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream(4096);
        private volatile boolean truncated = false;

        BoundedReader(InputStream in, long limit) {
            this.in = in;
            this.limit = limit;
        }

        @Override
        public void run() {
            byte[] chunk = new byte[4096];
            long total = 0;
            try {
                int n;
                while ((n = in.read(chunk)) != -1) {
                    total += n;
                    if (total <= limit) {
                        buffer.write(chunk, 0, n);
                    } else {
                        truncated = true;
                    }
                }
            } catch (IOException ignored) {
                // Expected when the process is killed (timeout) mid-read.
            }
        }

        String getOutput() {
            return buffer.toString(StandardCharsets.UTF_8);
        }

        boolean wasTruncated() {
            return truncated;
        }
    }
}
