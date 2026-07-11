"""
proxy/identity  (v4)

Identity & Trust: capability tokens, agent RBAC, secure sessions, and
memory integrity. The approval-gate generalization (per-capability
policies, history, escalation chains) lives with the gate itself in
proxy/runtime/approval.py.
"""

from proxy.identity.capabilities import (
    CapabilityIssuer, CapabilitySet, VerifyResult,
    capability_matches, target_matches, CORE_CAPABILITIES,
)
from proxy.identity.rbac import Rbac, RbacVerdict
from proxy.identity.sessions import SecureSession, SessionManager
from proxy.identity.memguard import (
    MemoryVault, MemoryIntegrityError, IntegrityViolation,
)

__all__ = [
    "CapabilityIssuer", "CapabilitySet", "VerifyResult",
    "capability_matches", "target_matches", "CORE_CAPABILITIES",
    "Rbac", "RbacVerdict",
    "SecureSession", "SessionManager",
    "MemoryVault", "MemoryIntegrityError", "IntegrityViolation",
]
