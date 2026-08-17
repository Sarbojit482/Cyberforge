package cyberforge.cli;

/**
 * Prints the CyberForge startup banner.
 */
public final class Banner {

    private Banner() {
    }

    public static void print() {
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║                      CYBERFORGE                           ║");
        System.out.println("║  Evidence-Driven Autonomous Cyber Reasoning & Repair      ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
        System.out.println();
    }

    public static void printVerifiedFix() {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════╗");
        System.out.println("║                  VERIFIED SECURITY FIX                     ║");
        System.out.println("╚══════════════════════════════════════════════════════════╝");
    }
}
