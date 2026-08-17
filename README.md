

Readme · MD
# CyberForge
 
**Evidence-Driven Autonomous Cyber Reasoning & Repair Engine**
 
CyberForge is a CLI tool that scans source code, runs real static analysis against it, and produces structured, tamper-evident evidence of vulnerabilities — the foundation for an eventual autonomous reasoning-and-repair pipeline.
 
> ⚠️ **Status: early-stage.** Target loading, static analysis, and evidence generation are implemented and working. Autonomous reasoning, patching, sandboxing, and dynamic testing are **not yet implemented** — see [Roadmap](#roadmap).
 
---
 
## Status
 
| Priority | Feature | Status |
|---|---|---|
| 1 | Java CLI + real target loading | ✅ Done |
| 2 | Real Semgrep integration | ✅ Done |
| 3 | Evidence JSON generation | ✅ Done |
| 4–11 | Local LLM reasoning, patch generation/application, regression & security testing, Docker sandbox, fuzzing, DAST | ❌ Not implemented |
 
`analyze` honestly reports when a capability isn't available yet instead of fabricating results. `repair` and `verify` are currently stubs.
 
**Priority 2 note:** Semgrep integration uses a **local ruleset** (`rules/basic-security.yml`) and never `--config=auto`. Analysis is fully offline — nothing is sent to Semgrep's registry or telemetry endpoints.
 
**Priority 3 note:** Findings are normalized into a common schema and written to `evidence/evidence-<timestamp>.json` with owner-only file permissions.
 
---
 
## Quick Start
 
### Build
 
```bash
javac -d out/classes -encoding UTF-8 $(find src/main/java -name "*.java")
jar --create --file out/cyberforge.jar --main-class cyberforge.Main -C out/classes .
```
 
> A Maven `pom.xml` is included for future use once you have network access to Maven Central. This project currently builds directly with `javac`/`jar`.
 
### Run
 
```bash
# Interactive REPL
java -jar out/cyberforge.jar
 
# Analyze a target directory
java -jar out/cyberforge.jar analyze targets/demo
```
 
`scan`, `help`, and `status` work regardless of environment. `analyze` requires [Semgrep](https://semgrep.dev/) on your `PATH`:
 
```bash
pip install semgrep
```
 
### Try the demo
 
`targets/demo/app.py` contains a deliberately vulnerable `run_ping()` function (OS command injection via `os.system()`), along with a reproducible security test at `targets/demo/tests/test_security.py`. The test currently **fails** against the vulnerable code and is expected to pass once Priority 6 (patch generation) lands.
 
```bash
java -jar out/cyberforge.jar analyze targets/demo
```
 
---
 
## Security Model
 
CyberForge treats **both** the target directory and CLI input as hostile by default — its whole job is pointing itself at untrusted source code and invoking external tools against it. Every control below is documented in-line at its enforcement point; search the codebase for `SECURITY`, `LAYER`, or `CONTROL` to find them.
 
| Layer | File(s) | Defends against |
|---|---|---|
| Input validation | `TargetLoader`, `CommandHandler` | NUL-byte / control-char injection, oversized arguments |
| Path confinement | `TargetLoader` | Scans of `/etc`, `../../..` traversal — targets must resolve inside an allow-listed root (default: CWD; widen with `CYBERFORGE_ALLOWED_ROOTS`) |
| Symlink-escape protection | `TargetLoader` | A symlink inside a target silently walking CyberForge outside the sandbox, or into a symlink loop |
| Special-file rejection | `TargetLoader` | Hanging reads / kernel data exposure from device files, FIFOs, sockets |
| Resource limits | `TargetLoader`, `util/SecurityLimits` | "Directory bomb" targets exhausting memory or looping forever (file count, per-file size, total size, depth caps) |
| Shared no-shell subprocess execution | `util/SafeProcessRunner` | Command injection — every external tool call (version checks and Semgrep) goes through one audited, fixed-argument-array runner |
| Sanitized child environment | `util/SafeProcessRunner` | `LD_PRELOAD` / `PYTHONPATH` / `NODE_OPTIONS` / etc. environment-based hijacking of invoked tools |
| Bounded, concurrent output draining | `util/SafeProcessRunner` | The classic Java `ProcessBuilder` stdout-pipe deadlock, and unbounded memory use from a misbehaving/compromised tool (Semgrep's JSON report gets a larger but still bounded cap than a version string) |
| Hard subprocess timeout | `util/SafeProcessRunner` | A hung external tool hanging CyberForge itself |
| Offline static analysis | `analysis/StaticAnalyzer` | `--config=auto`/registry calls that would leak target code or metadata over the network — uses a local ruleset + `--metrics=off` instead |
| Dependency-free, bounded JSON parsing | `util/Json` | No external JSON library (no Maven Central access in some build environments); a strict recursive-descent parser with no eval/reflection, so malformed/hostile Semgrep output can only throw, never execute |
| Evidence file permission hardening | `evidence/EvidenceManager` | Vulnerability findings are sensitive — evidence dir/files are written `700`/`600` (owner-only) wherever POSIX permissions are available |
| Fail-safe dispatch | `CLI`, `CommandHandler` | One bad command crashing the whole REPL session |
| No leaked internals | `CommandHandler`, `Main` | Raw stack traces / exception messages (which can embed absolute paths) reaching the operator's terminal |
| Least-privilege warning | `Main` | Advisory-only warning if run as root |
 
Every security decision made while loading a target (a skipped symlink, an oversized file excluded, a resource limit hit) is surfaced to the operator in `scan`/`analyze` output rather than silently hidden.
 
---
 
## Configuration
 
### Confinement roots
 
By default, targets must resolve inside the current working directory. To widen this:
 
```bash
export CYBERFORGE_ALLOWED_ROOTS="/data/targets:/mnt/shared-targets"
```
 
---
 
## Roadmap
 
The following components are planned but **not yet implemented**:
 
- **`ai/ReasoningEngine.java`** — talk to a local Ollama model, using the evidence JSON already produced by `EvidenceManager` as input, to generate structured vulnerability and patch recommendations.
- **`repair/PatchGenerator.java`** + **`PatchApplier.java`** — generate and apply patches based on reasoning output.
- **`testing/RegressionTester.java`** — run `targets/demo/tests/` (including `test_security.py`) before and after a patch to verify fixes and catch regressions.
- **`sandbox/DockerManager.java`** — isolated execution environment for untrusted code and patch verification.
- **`analysis/Fuzzer.java`** — fuzz testing integration.
- **DAST** — dynamic application security testing.
 
---
 
## License
 
_Add license information here._
 
