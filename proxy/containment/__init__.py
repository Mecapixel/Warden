"""
proxy/containment  (v5) — Runtime Containment.

Isolate execution environments and limit blast radius:

    backends.py   the isolation ladder (Docker -> gVisor -> Wasmtime),
                  injectable detection, required-or-stronger selection
    sandbox.py    provisioning — Warden constructs the spec; the floor
                  (network none, read-only root, cap-drop ALL) cannot be
                  breached (SBX-002)
    ephemeral.py  the writable surface that dies with the run, destruction
                  verified (EPH-001)
    quotas.py     CPU / memory / disk / pids / wall clock, validated at
                  load, host-held deadline (QUO-001)
    procmon.py    fork breaches, zombies, overstay, unexpected executables
                  (PROC-001..004), injectable process snapshots

Rendered argv in, nothing executed here: the transport spawns what
provisioning hands it, and every property of the containment posture is
assertable in tests on a host with no container runtime at all.
"""

from proxy.containment.backends import (            # noqa: F401
    BackendUnavailable, ISOLATION_ORDER, detect, select_backend)
from proxy.containment.sandbox import (              # noqa: F401
    ProvisionedSandbox, SandboxSpec, SpecViolation, provision)
from proxy.containment.ephemeral import EphemeralWorkspace   # noqa: F401
from proxy.containment.quotas import Deadline, Quotas, QuotaError  # noqa: F401
from proxy.containment.procmon import ProcessMonitor, ProcInfo  # noqa: F401
