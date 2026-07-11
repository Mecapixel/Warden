# proxy/network — the v3 Network Security subsystem.
#
# v1 shipped the minimal egress allowlist (deny unknown hosts). This package
# completes the network trust boundary: SSRF address-class enforcement with
# resolve-then-validate DNS pinning, sinkholing, per-tool egress scopes,
# domain reputation, rate limiting, download payload inspection, HTTP
# redirect/header inspection, and canary-token exfiltration tripwires.
#
# Design rules carried over from v1:
#   - Deny by default. Fail closed. A resolver error is a denial, not a pass.
#   - Detection can fail; enforcement cannot. Reputation and heuristics are
#     defense-in-depth; the allowlist and address-class checks are the wall.
#   - The agent never learns which rule stopped it.
