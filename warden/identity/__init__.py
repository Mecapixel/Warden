"""
warden/identity  (v4)

Identity & Trust: capability tokens, agent RBAC, secure sessions, and
memory integrity. The approval-gate generalization (per-capability
policies, history, escalation chains) lives with the gate itself in
warden/runtime/approval.py.
"""

from warden.identity.capabilities import (
    CapabilityIssuer, CapabilitySet, VerifyResult,
    capability_matches, target_matches, CORE_CAPABILITIES,
)
from warden.identity.rbac import Rbac, RbacVerdict
from warden.identity.sessions import SecureSession, SessionManager
from warden.identity.memguard import (
    MemoryVault, MemoryIntegrityError, IntegrityViolation,
)

__all__ = [
    "CapabilityIssuer", "CapabilitySet", "VerifyResult",
    "capability_matches", "target_matches", "CORE_CAPABILITIES",
    "Rbac", "RbacVerdict",
    "SecureSession", "SessionManager",
    "MemoryVault", "MemoryIntegrityError", "IntegrityViolation",
]
