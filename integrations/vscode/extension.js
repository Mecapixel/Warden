// Warden VS Code extension (v7, preview).
//
// Design: the extension holds NO policy logic. Every evaluation shells out to
// the same `warden` CLI the runtime uses, so what you see in the editor is
// exactly what the runtime will decide — one engine, no drift.
//
// Features:
//   * Warden: Inspect Tool Call   — prompt for tool + JSON args, show the
//                                   verdict, rule, and reasoning.
//   * Warden: Audit Stats         — telemetry snapshot in an output channel.
//   * Live policy validation      — on save of the policy file, revalidate
//                                   and reflect the result in the status bar.
//
// No bundler, no dependencies: plain extension-host JavaScript. Run it from
// source with F5 ("Run Extension") in VS Code, or package with `vsce package`.

const vscode = require("vscode");
const cp = require("child_process");
const path = require("path");

let statusItem;
let output;

function cfg(key) {
  return vscode.workspace.getConfiguration("warden").get(key);
}

function workspaceRoot() {
  const f = vscode.workspace.workspaceFolders;
  return f && f.length ? f[0].uri.fsPath : undefined;
}

function runWarden(args, cb) {
  const cwd = workspaceRoot();
  cp.execFile(cfg("executable"), args, { cwd, timeout: 15000 },
    (err, stdout, stderr) => cb(err, stdout || "", stderr || ""));
}

function policyArgs() {
  return ["--policy", path.join(workspaceRoot() || ".", cfg("policyPath"))];
}

function setStatus(ok, text) {
  statusItem.text = (ok ? "$(shield) " : "$(alert) ") + text;
  statusItem.tooltip = "Warden policy status";
  statusItem.show();
}

function validatePolicy() {
  // `warden inspect` with a throwaway tool exercises full policy load +
  // validation; a broken policy fails loudly before any verdict.
  runWarden([...policyArgs(), "inspect", "__warden_vscode_probe__"],
    (err, stdout, stderr) => {
      if (stderr.includes("policy error")) {
        setStatus(false, "Warden: policy INVALID");
        output.appendLine(stderr.trim());
      } else {
        setStatus(true, "Warden: policy OK");
      }
    });
}

async function inspectToolCall() {
  const tool = await vscode.window.showInputBox({
    prompt: "Tool name to evaluate (e.g. read_file)" });
  if (!tool) return;
  const args = await vscode.window.showInputBox({
    prompt: "Tool arguments as JSON (e.g. {\"path\": \"notes.txt\"})",
    value: "{}" });
  runWarden([...policyArgs(), "inspect", tool, args || "{}"],
    (err, stdout, stderr) => {
      output.clear();
      output.appendLine(stdout || stderr || String(err || ""));
      output.show(true);
      const m = /Decision:\s*(\w+)/.exec(stdout);
      if (m) {
        const v = m[1];
        const icon = v === "ALLOW" ? "$(check)" :
                     v === "DENY" ? "$(circle-slash)" : "$(question)";
        vscode.window.setStatusBarMessage(`${icon} warden: ${tool} → ${v}`, 8000);
      }
    });
}

function auditStats() {
  runWarden([...policyArgs(), "stats"], (err, stdout, stderr) => {
    output.clear();
    output.appendLine(stdout || stderr || String(err || ""));
    output.show(true);
  });
}

function activate(context) {
  output = vscode.window.createOutputChannel("Warden");
  statusItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left, 50);

  context.subscriptions.push(
    output, statusItem,
    vscode.commands.registerCommand("warden.inspect", inspectToolCall),
    vscode.commands.registerCommand("warden.stats", auditStats),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (doc.fileName.endsWith(cfg("policyPath")) ||
          doc.fileName.endsWith(".policy.yaml")) {
        validatePolicy();
      }
    }),
  );
  validatePolicy();
}

function deactivate() {}

module.exports = { activate, deactivate };
