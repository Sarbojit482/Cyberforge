package cyberforge.model;

import java.util.List;

/**
 * Represents a target source-code project loaded from disk.
 *
 * SECURITY NOTE: every field here is populated from a REAL, security-checked
 * filesystem walk (see cyberforge.cli.TargetLoader) — never fabricated. The
 * skippedEntries/limitReached fields exist specifically so that security
 * decisions made during loading (a symlink not followed, a file over the size
 * cap, a resource limit hit) are surfaced to the operator rather than silently
 * hidden — silent security truncation is itself a risk (it can mask the true
 * scope of what was actually analyzed).
 */
public class Target {

    private final String path;
    private final List<String> sourceFiles;
    private final long totalSizeBytes;
    private final String primaryLanguage;

    private List<String> skippedEntries = List.of();
    private boolean limitReached = false;

    public Target(String path, List<String> sourceFiles, long totalSizeBytes, String primaryLanguage) {
        this.path = path;
        this.sourceFiles = sourceFiles;
        this.totalSizeBytes = totalSizeBytes;
        this.primaryLanguage = primaryLanguage;
    }

    public String getPath() {
        return path;
    }

    public List<String> getSourceFiles() {
        return sourceFiles;
    }

    public long getTotalSizeBytes() {
        return totalSizeBytes;
    }

    public String getPrimaryLanguage() {
        return primaryLanguage;
    }

    public int getFileCount() {
        return sourceFiles.size();
    }

    public List<String> getSkippedEntries() {
        return skippedEntries;
    }

    public void setSkippedEntries(List<String> skippedEntries) {
        this.skippedEntries = skippedEntries == null ? List.of() : skippedEntries;
    }

    public boolean isLimitReached() {
        return limitReached;
    }

    public void setLimitReached(boolean limitReached) {
        this.limitReached = limitReached;
    }
}
