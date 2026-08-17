package cyberforge.cli;

import cyberforge.model.Target;
import cyberforge.util.SecurityLimits;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Loads a target project from a real path on disk.
 *
 * ================================ SECURITY MODEL ================================
 * This class touches UNTRUSTED input on two fronts: the raw path string typed by
 * the operator, and the (potentially adversarial) contents of the target directory
 * itself. Five independent layers of defense are applied, in order, so that a bug
 * in any single layer does not by itself create a vulnerability:
 *
 *  LAYER 1 — INPUT VALIDATION
 *      The raw path string is checked for NUL bytes / control characters and an
 *      excessive length BEFORE it is ever handed to the filesystem APIs. NUL-byte
 *      injection into path strings is a classic technique for confusing native
 *      filesystem layers; rejecting it up front closes that class of bug entirely.
 *
 *  LAYER 2 — PATH CONFINEMENT (anti path-traversal)
 *      The resolved, *real* (symlink-resolved) target path must live inside one of
 *      the configured "allowed roots" (by default: the current working directory).
 *      This stops `scan /etc`, `scan ../../../../root`, or a symlink planted inside
 *      an otherwise-legitimate target from ever letting CyberForge read files
 *      outside the operator's intended sandbox. Allowed roots can be widened via
 *      the CYBERFORGE_ALLOWED_ROOTS environment variable (path-separator-delimited)
 *      for operators who intentionally want to scan elsewhere.
 *
 *  LAYER 3 — SYMLINK-ESCAPE PROTECTION
 *      Symlinks are NEVER followed while walking (Files.walkFileTree's default
 *      behavior — FOLLOW_LINKS is intentionally not enabled). Every symlink
 *      encountered is recorded as skipped rather than silently traversed, which
 *      prevents a symlink planted inside a target from walking CyberForge out to
 *      arbitrary filesystem locations or into an infinite symlink loop.
 *
 *  LAYER 4 — SPECIAL-FILE REJECTION
 *      Only regular files and directories are processed. Device files, FIFOs/named
 *      pipes, and sockets are skipped — reading them can hang indefinitely or
 *      expose kernel-side data never intended to be treated as "source code".
 *
 *  LAYER 5 — RESOURCE LIMITS (anti resource-exhaustion)
 *      File count, per-file size, total size, and directory depth are all capped
 *      (see SecurityLimits) so a hostile or pathological target ("directory bomb")
 *      cannot exhaust memory or make the walk run indefinitely. Walking stops the
 *      instant a limit is hit and the truncation is reported honestly, never hidden.
 * ===================================================================================
 */
public final class TargetLoader {

    private static final Map<String, String> EXTENSION_LANGUAGE = Map.ofEntries(
            Map.entry(".py", "Python"),
            Map.entry(".java", "Java"),
            Map.entry(".js", "JavaScript"),
            Map.entry(".ts", "TypeScript"),
            Map.entry(".go", "Go"),
            Map.entry(".rs", "Rust"),
            Map.entry(".c", "C"),
            Map.entry(".cpp", "C++"),
            Map.entry(".rb", "Ruby"),
            Map.entry(".php", "PHP")
    );

    /**
     * Loads a target. Throws IOException with a short, safe (non-leaky) message
     * for every failure mode — callers should show e.getMessage() directly to the
     * operator without appending raw stack traces.
     */
    public Target load(String rawPath) throws IOException {
        // ---- LAYER 1: input validation, before touching the filesystem at all ----
        validateRawPath(rawPath);

        Path requested = Paths.get(rawPath).toAbsolutePath().normalize();

        if (!Files.exists(requested, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Path does not exist: " + requested);
        }

        // Resolve the REAL path (following any symlink on the root itself exactly
        // once, explicitly, so we know the true destination) before confinement is
        // checked — checking confinement on the un-resolved path would let a
        // symlinked target directory bypass the confinement check entirely.
        Path realRoot;
        try {
            realRoot = requested.toRealPath();
        } catch (IOException e) {
            // Covers unresolvable symlinks and symlink loops (ELOOP) alike.
            throw new IOException("Could not resolve path (possible symlink loop): " + requested);
        }

        // ---- LAYER 2: path confinement ----
        enforceConfinement(realRoot);

        List<String> files = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        long[] totalBytes = {0L};
        int[] fileCount = {0};
        Map<String, Integer> languageCounts = new HashMap<>();
        boolean[] limitHit = {false};

        if (Files.isRegularFile(realRoot, LinkOption.NOFOLLOW_LINKS)) {
            recordFile(realRoot, realRoot, files, totalBytes, fileCount, languageCounts, skipped);
        } else if (Files.isDirectory(realRoot, LinkOption.NOFOLLOW_LINKS)) {
            walk(realRoot, files, totalBytes, fileCount, languageCounts, skipped, limitHit);
        } else {
            // ---- LAYER 4: special-file rejection (root itself is special) ----
            throw new IOException("Refusing to load non-regular, non-directory path: " + realRoot);
        }

        files.sort(Comparator.naturalOrder());

        String primaryLanguage = languageCounts.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse("unknown");

        Target target = new Target(realRoot.toString(), files, totalBytes[0], primaryLanguage);
        target.setSkippedEntries(skipped);
        target.setLimitReached(limitHit[0]);
        return target;
    }

    // -----------------------------------------------------------------
    // LAYER 1: input validation
    // -----------------------------------------------------------------
    private void validateRawPath(String rawPath) throws IOException {
        if (rawPath == null || rawPath.isBlank()) {
            throw new IOException("Path must not be empty");
        }
        if (rawPath.length() > SecurityLimits.MAX_PATH_ARG_LENGTH) {
            throw new IOException("Path exceeds maximum accepted length ("
                    + SecurityLimits.MAX_PATH_ARG_LENGTH + " chars)");
        }
        // Reject NUL bytes and other control characters. NUL-byte injection into
        // path strings is a well-known technique for confusing native filesystem
        // layers (e.g. truncating a path check while the OS still opens the full
        // string) — rejecting it here, before any filesystem call, is cheap and
        // closes that entire bug class regardless of how the JVM/OS would have
        // actually behaved.
        for (int i = 0; i < rawPath.length(); i++) {
            char c = rawPath.charAt(i);
            if (c == '\0' || (Character.isISOControl(c) && c != '\t')) {
                throw new IOException("Path contains an illegal control character");
            }
        }
    }

    // -----------------------------------------------------------------
    // LAYER 2: path confinement
    // -----------------------------------------------------------------

    /**
     * Determines the set of directories CyberForge is allowed to read targets
     * from. Defaults to just the current working directory (the safest default —
     * an operator has to opt in to scanning anywhere else) but can be widened via
     * CYBERFORGE_ALLOWED_ROOTS for legitimate use cases (e.g. a shared "targets/"
     * volume mounted elsewhere in a container).
     */
    private List<Path> allowedRoots() throws IOException {
        List<Path> roots = new ArrayList<>();
        String configured = System.getenv("CYBERFORGE_ALLOWED_ROOTS");
        if (configured != null && !configured.isBlank()) {
            for (String part : configured.split(java.io.File.pathSeparator)) {
                if (part.isBlank()) {
                    continue;
                }
                roots.add(Paths.get(part).toAbsolutePath().normalize().toRealPath());
            }
        } else {
            roots.add(Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize().toRealPath());
        }
        return roots;
    }

    private void enforceConfinement(Path realRoot) throws IOException {
        List<Path> allowed = allowedRoots();
        for (Path root : allowed) {
            if (realRoot.equals(root) || realRoot.startsWith(root)) {
                return; // confined — OK
            }
        }
        throw new IOException("Refusing to load target outside the allowed root(s) "
                + allowed + ". Set CYBERFORGE_ALLOWED_ROOTS to permit this path if intentional.");
    }

    // -----------------------------------------------------------------
    // LAYERS 3-5: symlink protection, special-file rejection, resource limits
    // -----------------------------------------------------------------
    private void walk(Path realRoot, List<String> files, long[] totalBytes, int[] fileCount,
                       Map<String, Integer> languageCounts, List<String> skipped, boolean[] limitHit)
            throws IOException {

        Files.walkFileTree(realRoot, java.util.EnumSet.noneOf(java.nio.file.FileVisitOption.class),
                SecurityLimits.MAX_DIRECTORY_DEPTH, new SimpleFileVisitor<Path>() {

            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (limitHit[0]) {
                    return FileVisitResult.TERMINATE;
                }
                // LAYER 3: never descend into a symlinked directory.
                if (attrs.isSymbolicLink()) {
                    skipped.add(realRoot.relativize(dir) + " (symlink directory — not followed)");
                    return FileVisitResult.SKIP_SUBTREE;
                }
                // Skip VCS/hidden directories (.git, .hg, etc.) — not a security
                // control by itself, just keeps output relevant, but also reduces
                // the amount of untrusted content walked (smaller attack surface).
                String name = dir.getFileName() == null ? "" : dir.getFileName().toString();
                if (name.startsWith(".") && !dir.equals(realRoot)) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (limitHit[0]) {
                    return FileVisitResult.TERMINATE;
                }

                // LAYER 3: never read through a symlinked file.
                if (attrs.isSymbolicLink()) {
                    skipped.add(realRoot.relativize(file) + " (symlink file — not followed)");
                    return FileVisitResult.CONTINUE;
                }
                // LAYER 4: only regular files are processed; device files, FIFOs,
                // and sockets are explicitly rejected (reading them can hang or
                // expose data never intended to be treated as source code).
                if (!attrs.isRegularFile()) {
                    skipped.add(realRoot.relativize(file) + " (not a regular file — skipped)");
                    return FileVisitResult.CONTINUE;
                }

                // LAYER 5: per-file and aggregate resource limits.
                if (attrs.size() > SecurityLimits.MAX_SINGLE_FILE_BYTES) {
                    skipped.add(realRoot.relativize(file) + " (exceeds per-file size limit — skipped)");
                    return FileVisitResult.CONTINUE;
                }
                if (fileCount[0] + 1 > SecurityLimits.MAX_FILES) {
                    limitHit[0] = true;
                    skipped.add("... file-count limit (" + SecurityLimits.MAX_FILES + ") reached, stopping walk");
                    return FileVisitResult.TERMINATE;
                }
                if (totalBytes[0] + attrs.size() > SecurityLimits.MAX_TOTAL_BYTES) {
                    limitHit[0] = true;
                    skipped.add("... total size limit (" + SecurityLimits.MAX_TOTAL_BYTES + " bytes) reached, stopping walk");
                    return FileVisitResult.TERMINATE;
                }

                files.add(realRoot.relativize(file).toString());
                totalBytes[0] += attrs.size();
                fileCount[0]++;
                recordLanguage(file, languageCounts);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                // Fail OPEN for a single unreadable entry (permission denied, race
                // condition, etc.) rather than aborting the whole scan — but the
                // skip is recorded so the operator can see it happened.
                skipped.add(safeRelativize(realRoot, file) + " (unreadable: " + safeReason(exc) + ")");
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private void recordFile(Path root, Path file, List<String> files, long[] totalBytes, int[] fileCount,
                             Map<String, Integer> languageCounts, List<String> skipped) throws IOException {
        long size = Files.size(file);
        if (size > SecurityLimits.MAX_SINGLE_FILE_BYTES) {
            skipped.add(root.relativize(file) + " (exceeds per-file size limit — skipped)");
            return;
        }
        files.add(root.relativize(file).toString());
        totalBytes[0] += size;
        fileCount[0]++;
        recordLanguage(file, languageCounts);
    }

    private void recordLanguage(Path file, Map<String, Integer> languageCounts) {
        String name = file.getFileName().toString();
        int dot = name.lastIndexOf('.');
        if (dot >= 0) {
            String ext = name.substring(dot).toLowerCase(Locale.ROOT);
            String lang = EXTENSION_LANGUAGE.get(ext);
            if (lang != null) {
                languageCounts.merge(lang, 1, Integer::sum);
            }
        }
    }

    private String safeRelativize(Path root, Path file) {
        try {
            return root.relativize(file).toString();
        } catch (IllegalArgumentException e) {
            return file.toString();
        }
    }

    /** Never leak raw exception internals (which can include sensitive absolute
     *  paths from other parts of the system) — just a short, safe category. */
    private String safeReason(IOException exc) {
        return exc.getClass().getSimpleName();
    }
}
