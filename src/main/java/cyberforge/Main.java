package cyberforge;

import cyberforge.cli.CLI;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * CyberForge entry point.
 *
 * Usage:
 *   cyberforge                      Interactive mode (cyberforge> prompt)
 *   cyberforge analyze ./target     Single-shot mode
 *   cyberforge scan ./target
 *   cyberforge status
 *   cyberforge help
 *
 * SECURITY MODEL:
 *  - A global uncaught-exception handler is installed FIRST, before anything
 *    else runs, so that if some bug anywhere in the JVM produces an exception
 *    that escapes every other layer's own error handling, the operator still
 *    never sees a raw stack trace (which could embed absolute paths or other
 *    environment details) printed to their terminal.
 *  - stdout/stderr are forced to UTF-8 explicitly rather than relying on the
 *    host's default locale/charset, so output is predictable and correctly
 *    encoded on any machine (not itself a security control, but predictable
 *    output is a prerequisite for anyone auditing what CyberForge prints).
 *  - CyberForge warns (but does not refuse to run) if started as root: this
 *    tool shells out to other binaries and walks arbitrary target
 *    directories, so running it with more privilege than necessary widens
 *    the blast radius of any bug in CyberForge itself or in a tool it
 *    invokes. The warning follows the principle of least privilege without
 *    breaking legitimate containerized/CI setups that may run as root.
 */
public class Main {

    public static void main(String[] args) {
        installGlobalUncaughtExceptionHandler();

        // Force UTF-8 stdout/stderr regardless of the host's default locale, so
        // the box-drawing / checkmark characters in the banner and status output
        // render correctly on any machine (e.g. a POSIX/C-locale CI box).
        System.setOut(new PrintStream(System.out, true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(System.err, true, StandardCharsets.UTF_8));

        warnIfRunningAsRoot();

        CLI cli = new CLI();
        boolean ok = cli.startup();
        if (!ok) {
            System.out.println("[!] CyberForge cannot start.");
            System.exit(1);
        }

        if (args.length > 0) {
            cli.runSingleCommand(args);
        } else {
            cli.runInteractive();
        }
    }

    /**
     * Ensures that no exception, from any thread, can ever print a raw Java
     * stack trace to the operator's terminal. Logs a short, safe summary
     * instead. This is the outermost safety net; every layer beneath this
     * (CLI, CommandHandler, SystemChecker, TargetLoader) already catches and
     * safely reports its own expected failure modes — this only fires for
     * truly unexpected bugs.
     */
    private static void installGlobalUncaughtExceptionHandler() {
        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) -> {
            System.err.println("[!] CyberForge encountered an internal error and must stop this operation ("
                    + throwable.getClass().getSimpleName() + ").");
        });
    }

    /**
     * Best-effort, non-blocking check for root/administrator execution. This is
     * advisory only (principle of least privilege) — it never prevents
     * CyberForge from running, since some legitimate environments (containers,
     * CI runners) execute everything as root by default.
     */
    private static void warnIfRunningAsRoot() {
        String user = System.getProperty("user.name", "");
        if ("root".equalsIgnoreCase(user)) {
            System.out.println("[!] CyberForge is running as root. This tool executes external");
            System.out.println("    binaries and reads arbitrary target directories — running as a");
            System.out.println("    non-privileged user is strongly recommended (principle of least");
            System.out.println("    privilege).");
            System.out.println();
        }
    }
}
