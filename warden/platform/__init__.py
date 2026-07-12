"""
warden/platform  (v7) — productization layer.

  bundle     shareable policy bundles: hash-pinned, Ed25519-signed,
             deny-by-default install (the marketplace format).
  dashboard  localhost-only, token-authenticated web dashboard over the
             audit chain, telemetry, sessions, policy, and the v6 replay
             engine; also the engine behind `warden desktop`.
"""

from warden.platform.bundle import (                       # noqa: F401
    BundleError, SigningUnavailable, VerifyReport,
    keygen, pack, verify, install,
)
from warden.platform.dashboard import DashboardServer, open_desktop  # noqa: F401
