package cyberforge.util;

/**
 * SECURITY: centralized hard limits enforced throughout CyberForge.
 *
 * CyberForge's entire job is to point itself at UNTRUSTED source code
 * (the "target") and invoke external tools against it. That means two
 * distinct trust boundaries exist and must both be defended:
 *
 *   (A) The target directory/files on disk — untrusted content, possibly
 *       adversarial (a malicious target could contain symlink loops, huge
 *       files, deeply nested directories, or special files designed to
 *       hang or exhaust a naive scanner).
 *
 *   (B) Interactive CLI input from stdin — untrusted in the sense that
 *       CyberForge should never crash, hang, or misbehave no matter what
 *       is typed or piped into it.
 *
 * Every numeric/behavioral boundary CyberForge enforces against those two
 * surfaces is declared here, with the reasoning next to it, so the whole
 * security posture can be reviewed in one file instead of being scattered
 * (and potentially forgotten) across the codebase.
 */
public final class SecurityLimits {

    private SecurityLimits() {
        // Constants-only holder; never instantiated.
    }

    // ---------------------------------------------------------------
    // (A) Target-loading limits — defend against a hostile/pathological
    //     target directory ("directory bomb") exhausting memory or
    //     spinning forever.
    // ---------------------------------------------------------------

    /** Maximum number of files CyberForge will index from a single target. */
    public static final int MAX_FILES = 20_000;

    /** Maximum combined size (bytes) of all files counted from a target. */
    public static final long MAX_TOTAL_BYTES = 500L * 1024 * 1024; // 500 MB

    /** Maximum size (bytes) of any single file that will be counted/read. */
    public static final long MAX_SINGLE_FILE_BYTES = 50L * 1024 * 1024; // 50 MB

    /** Maximum directory nesting depth walked below the target root. */
    public static final int MAX_DIRECTORY_DEPTH = 64;

    // ---------------------------------------------------------------
    // (B) Interactive CLI input limits — defend against unbounded memory
    //     allocation from a single absurd line of stdin input.
    // ---------------------------------------------------------------

    /** Maximum length (chars) accepted for a single REPL input line. */
    public static final int MAX_COMMAND_LINE_LENGTH = 4096;

    /** Maximum length (chars) accepted for a path-like CLI argument. */
    public static final int MAX_PATH_ARG_LENGTH = 4096;

    // ---------------------------------------------------------------
    // (C) External subprocess limits — semgrep/docker/ollama/rustc are
    //     trusted binaries, but their OUTPUT is still treated as
    //     untrusted-sized: a broken, hung, or compromised binary must not
    //     be able to exhaust heap or hang CyberForge indefinitely.
    // ---------------------------------------------------------------

    /** Maximum bytes of subprocess stdout/stderr CyberForge will buffer. */
    public static final long MAX_PROCESS_OUTPUT_BYTES = 2L * 1024 * 1024; // 2 MB

    /** Hard wall-clock timeout for any single subprocess invocation. */
    public static final long PROCESS_TIMEOUT_SECONDS = 10;
}
