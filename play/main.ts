#!/usr/bin/env -S rote play run
/**
 * @rote-frontmatter
 * ---
 * name: log-leak-map
 * description: "Everyone hunts secrets in git history. This hunts log/output sinks. One row per Python/JS logging call — CONFIRMED SINK / SENSITIVE / SUSPICIOUS, DEBUG as a modifier, redacted reconstruction. Read-only, zero adapters, Python stdlib."
 * provenance:
 *   author: rajgharat07
 *   tier: local
 *   created_at: 2026-09-03T18:00:00.000000+00:00
 *   workspace: log-leak-map
 *   rote_version: 0.77.0
 * metadata:
 *   rote_version: 0.77.0
 *   version: 0.1.0
 *   status: released
 *   kind: atomic
 *   flow_type: sequential
 *   execution_model: steps_with_presentation
 *   requires_endpoints: []
 *   requires_sessions: false
 *   exploration_model: null
 *   discoverability:
 *     tags:
 *     - domain-engineering
 *     - engineering-workflows
 *     - job-security
 *     - tool-shell
 *     - effect-read-only
 * parameters:
 * - name: repo_path
 *   param_type: string
 *   required: true
 *   default: .
 *   description: Path to the repository to scan for leaking log statements
 *   example: .
 *   valid_values: null
 * - name: include_deps
 *   param_type: string
 *   required: false
 *   default: "false"
 *   description: When "true", also scan dependency directories (node_modules, site-packages, vendor)
 *   example: "false"
 *   valid_values: null
 * - name: scope
 *   param_type: string
 *   required: false
 *   default: ''
 *   description: Optional comma-separated glob(s) to narrow the scan
 *   example: "*.py,api"
 *   valid_values: null
 * steps:
 *   scan_log_leak_map:
 *     type: process.exec
 *     timeout_ms: 180000
 *     argv:
 *     - bash
 *     - '@resource{scan.sh}'
 *     - $repo_path
 *     - $include_deps
 *     - $scope
 * ---
 */

const presentationSdk = await import("__ROTE_PRESENTATION_SDK__").catch((cause) => {
  throw new Error(
    "This is a rote steps presentation program. Run it with `rote play run <path>`.",
    { cause },
  );
});
const { FlowOutput, isProcessExecBody, loadPresentationContext, stepName } =
  presentationSdk;

const out = new FlowOutput();
const ctx = await loadPresentationContext();
const scan = ctx.requireAvailable(stepName("scan_log_leak_map"));

if (!isProcessExecBody(scan.body)) {
  throw new Error("scan_log_leak_map did not record a process.exec observation");
}
if (scan.body.status.exit.kind !== "code" || scan.body.status.exit.code !== 0) {
  throw new Error(
    `scan_log_leak_map failed: ${scan.body.stderr?.text ?? "no stderr captured"}`,
  );
}

const report = scan.body.stdout?.text;
if (report === undefined) {
  throw new Error("scan_log_leak_map captured no stdout");
}

const repoPath = ctx.params.repo_path;
const includeDeps = ctx.params.include_deps;
const scope = ctx.params.scope;

if (typeof repoPath !== "string") {
  throw new Error("repo_path must be a string");
}

const trimmed = report.trimEnd();
const summaryLine =
  trimmed.split("\n").find((line) =>
    /LEAKING|SENSITIVE|RISKY|NEEDS-REVIEW|CLEAN|CONFIRMED SINK/.test(line)
  ) ??
  trimmed.split("\n").find((line) => line.startsWith("#")) ??
  "Log leak map scan completed";

out.human(trimmed);
out.summary(summaryLine.replace(/^#+\s*/, "").replace(/\*\*/g, "").trim());
out.result({
  run_id: ctx.run.run_id,
  repo_path: repoPath,
  include_deps: typeof includeDeps === "string" ? includeDeps : "false",
  scope: typeof scope === "string" && scope.length > 0 ? scope : null,
  report_markdown: trimmed,
  github_tool: "https://github.com/rajgharat07/log-leak-map",
});
