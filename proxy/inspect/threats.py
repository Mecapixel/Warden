"""
proxy/inspect/threats.py  (v2 — Model Security)

Expanded adversarial-content detection, layered on top of the v1 inbound
heuristics. Everything here is DEFENSE-IN-DEPTH: it produces signals, never
verdicts, and the v1 policy enforcement layer remains the control. A missed
signal here still hits the deny-by-default policy wall.

Detection classes (roadmap v2):
  * role_confusion   — fake system/assistant turns, role-switch framing
  * jailbreak        — known jailbreak scaffolds (DAN, "hypothetically", etc.)
  * hidden_unicode   — tag characters, private-use, excessive bidi/zero-width
                       density that survived (or targets) normalization
  * markup_abuse     — markdown/HTML used to smuggle or hide directives
  * context_abuse    — token flooding, oversized payloads, excessive entropy
                       (a payload engineered to blow the context window or
                       bury a directive under noise)

Each detector returns InjectionSignal objects (same dataclass the v1 inbound
inspector uses) so the mediator, audit, and policy code need zero changes.
"""

import math
import re
import unicodedata
from collections import Counter

from proxy.inspect.inbound import InjectionSignal, _excerpt
from proxy.core.textnorm import harden, _INVISIBLES


# --- role confusion / conversation-structure spoofing ----------------------
_ROLE_PATTERNS = [
    (r"(?:^|\n)\s*(?:system|assistant|developer)\s*:", 0.75),
    (r"<\|?(?:im_start|im_end|system|assistant|endoftext)\|?>", 0.9),
    (r"\[/?(?:INST|SYS|s)\]", 0.85),
    (r"###\s*(?:system|instruction|human|assistant)\s*(?:prompt|message)?", 0.7),
    (r"(?:you are|act as|pretend to be) (?:a |an )?(?:different|new) (?:ai|assistant|system)", 0.7),
]

# --- jailbreak scaffolds ---------------------------------------------------
_JAILBREAK_PATTERNS = [
    (r"\bDAN\b.{0,40}(?:mode|jailbreak|do anything)", 0.85),
    (r"do anything now", 0.8),
    (r"developer mode (?:enabled|output|v2)", 0.8),
    (r"(?:hypothetically|in a fictional (?:story|world|scenario)),?.{0,60}"
     r"(?:how (?:would|to)|steps to|instructions for)", 0.6),
    (r"you have no (?:restrictions|filters|guidelines|rules)", 0.8),
    (r"(?:ignore|bypass|disable) (?:your )?(?:safety|content|ethical) "
     r"(?:guidelines|filters|policies|restrictions)", 0.85),
    (r"respond (?:only )?as (?:an )?(?:unfiltered|uncensored|amoral)", 0.8),
    (r"begin (?:your )?(?:reply|response|answer) with ['\"]?(?:sure|certainly|absolutely)", 0.6),
]

# --- markdown / HTML smuggling (superset of v1 hidden-markup) ---------------
_MARKUP_PATTERNS = [
    (r"<(?:script|iframe|object|embed|svg)\b", 0.7),
    (r"<img[^>]+onerror\s*=", 0.8),
    (r"data:text/html", 0.7),
    (r"\]\(\s*(?:javascript|data):", 0.75),
    (r"<[a-z]+[^>]*\bstyle\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|"
     r"font-size\s*:\s*0|color\s*:\s*(?:#fff|white)|opacity\s*:\s*0)", 0.7),
]

_TAG_BLOCK_RE = re.compile(r"[\U000E0000-\U000E007F]")   # Unicode Tags block
_PUA_RE = re.compile(r"[\uE000-\uF8FF\U000F0000-\U000FFFFD]")  # private use

# Context-window abuse thresholds. Deliberately generous — these catch
# engineered flooding, not ordinary long documents.
_MAX_CHARS = 100_000
_MAX_TOKEN_APPROX = 25_000        # ~chars/4
_ENTROPY_FLOOR = 4.5              # bits/char; natural language ~3.5-4.2
_ENTROPY_MIN_LEN = 2_000         # only judge entropy on substantial text


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def detect_role_confusion(text: str) -> list[InjectionSignal]:
    return _scan(text, _ROLE_PATTERNS, "role_confusion",
                 flags=re.IGNORECASE | re.MULTILINE)


def detect_jailbreak(text: str) -> list[InjectionSignal]:
    return _scan(text, _JAILBREAK_PATTERNS, "jailbreak",
                 flags=re.IGNORECASE | re.DOTALL)


def detect_markup_abuse(text: str) -> list[InjectionSignal]:
    return _scan(text, _MARKUP_PATTERNS, "markup_abuse",
                 flags=re.IGNORECASE | re.DOTALL)


def detect_hidden_unicode(text: str) -> list[InjectionSignal]:
    """Detect hidden/obfuscating Unicode. Scans the RAW text (pre-harden):
    the presence of tag chars, private-use chars, or a high density of
    invisibles is itself the signal — harden() would erase the evidence."""
    if not text:
        return []
    signals: list[InjectionSignal] = []

    m = _TAG_BLOCK_RE.search(text)
    if m:
        signals.append(InjectionSignal(
            "hidden_unicode:tag_chars",
            "Unicode Tags-block characters present (invisible instruction smuggling)",
            0.9))
    m = _PUA_RE.search(text)
    if m:
        signals.append(InjectionSignal(
            "hidden_unicode:private_use",
            "private-use-area characters present", 0.6))

    invisibles = sum(1 for ch in text if ch in _INVISIBLES)
    if invisibles >= 5 and invisibles / max(len(text), 1) > 0.02:
        signals.append(InjectionSignal(
            "hidden_unicode:invisible_density",
            f"{invisibles} invisible/bidi characters "
            f"({invisibles / len(text):.0%} of text)", 0.7))

    # Bidi override/embed specifically (RLO attacks reorder visible text).
    if any(ch in text for ch in ("\u202e", "\u202d", "\u2066", "\u2067")):
        signals.append(InjectionSignal(
            "hidden_unicode:bidi_override",
            "bidirectional override/isolate characters present", 0.75))

    return signals


def detect_context_abuse(text: str) -> list[InjectionSignal]:
    """Token flooding, oversized prompts, excessive entropy — payloads
    engineered to overflow the context window or bury a directive in noise."""
    if not text:
        return []
    signals: list[InjectionSignal] = []
    n = len(text)

    if n > _MAX_CHARS:
        signals.append(InjectionSignal(
            "context_abuse:oversized",
            f"payload is {n} chars (> {_MAX_CHARS} threshold)", 0.6))
    approx_tokens = n // 4
    if approx_tokens > _MAX_TOKEN_APPROX:
        signals.append(InjectionSignal(
            "context_abuse:token_flood",
            f"~{approx_tokens} tokens (> {_MAX_TOKEN_APPROX} threshold)", 0.6))

    if n >= _ENTROPY_MIN_LEN:
        ent = _shannon(text)
        if ent > _ENTROPY_FLOOR:
            signals.append(InjectionSignal(
                "context_abuse:high_entropy",
                f"entropy {ent:.2f} bits/char over {n} chars "
                f"(> {_ENTROPY_FLOOR}; possible noise-flooding)", 0.5))

    return signals


# All v2 detectors, in one call, for the mediator and the miss-rate harness.
_ALL_DETECTORS = (
    detect_role_confusion,
    detect_jailbreak,
    detect_markup_abuse,
    detect_hidden_unicode,
    detect_context_abuse,
)


def inspect_expanded(text: str) -> list[InjectionSignal]:
    """Run every v2 detector and return the combined signals. Hidden-unicode
    and context-abuse detectors see RAW text; the phrase detectors see the
    hardened form so obfuscation inside a directive cannot hide it."""
    if not text:
        return []
    hardened = harden(text)
    signals: list[InjectionSignal] = []
    signals += detect_role_confusion(hardened)
    signals += detect_jailbreak(hardened)
    signals += detect_markup_abuse(hardened)
    signals += detect_hidden_unicode(text)      # raw on purpose
    signals += detect_context_abuse(text)       # raw on purpose
    return signals


def _scan(text, patterns, label, flags):
    if not text:
        return []
    out = []
    for pat, sev in patterns:
        for m in re.finditer(pat, text, flags):
            out.append(InjectionSignal(f"{label}:{pat[:30]}",
                                       _excerpt(text, m.start(), m.end()), sev))
    return out
