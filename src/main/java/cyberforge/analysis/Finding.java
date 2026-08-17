package cyberforge.analysis;

/**
 * A single normalized static-analysis finding, independent of which tool
 * produced it (currently always Semgrep, but this shape is what
 * EvidenceManager and, later, the AI reasoning engine consume — keeping it
 * tool-agnostic means DAST/fuzzing findings can be normalized the same way).
 */
public record Finding(
        String ruleId,
        String filePath,
        int startLine,
        int endLine,
        String severity,
        String message,
        String snippet
) {
}
