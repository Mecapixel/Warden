# Warden for VS Code (preview)

Live policy decisions while you develop agents. The extension holds no policy
logic of its own — every evaluation shells out to the same `warden` CLI the
runtime uses, so the editor shows exactly what the runtime will decide.

## Commands

Warden: Inspect Tool Call — enter a tool name and JSON args, get the verdict,
governing rule, risk score, and reasoning in the Warden output channel.

Warden: Audit Stats — the telemetry snapshot (`warden stats`) in the editor.

Saving your policy file revalidates it automatically; the status bar shows
"Warden: policy OK" or "Warden: policy INVALID".

## Requirements

`pip install warden-security` (or set `warden.executable` to the binary), and
a policy file in the workspace (`warden init`). Settings: `warden.policyPath`
(default `warden.policy.yaml`), `warden.executable` (default `warden`).

## Running from source

Open this folder in VS Code and press F5 ("Run Extension"). To package a
.vsix: `npm install -g @vscode/vsce && vsce package`. This extension is
shipped as source in the Warden repo (preview status); it is not yet on the
Marketplace.
