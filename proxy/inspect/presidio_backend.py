"""
proxy/inspect/presidio_backend.py  (v1.5.5)

Optional Presidio detector backend behind the existing detector interface.

Design contract (per ROADMAP v1.5.5):
  * Regex + entropy stay the lightweight default. Presidio is an OPT-IN
    adapter for richer PII (names, locations, phone numbers, national IDs) —
    never a replacement. Enabling it ADDS findings; it removes nothing.
  * Fail loud, not silently weaker: if policy explicitly enables the
    "presidio" detector and the backend cannot load, policy validation
    raises at startup. A security tool must never quietly downgrade the
    detection the operator configured.
  * Zero cost when unused: nothing here imports presidio (or spaCy) unless
    the detector is actually enabled.

Enable in policy.yaml:
    redaction:
      enabled: true
      detectors: [aws_keys, api_keys, presidio]

Install the optional dependency:
    pip install presidio-analyzer
    pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # import only for type checkers; runtime stays lazy
    from proxy.inspect.redactor import Finding

# Entities worth flagging in tool-call traffic. PERSON/LOCATION are noisy in
# code-heavy text, so the default set is deliberately conservative; operators
# can widen it via redaction.presidio_entities in policy.yaml.
DEFAULT_ENTITIES = [
    "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD",
    "IBAN_CODE", "IP_ADDRESS", "US_PASSPORT", "US_DRIVER_LICENSE",
]
DEFAULT_MIN_SCORE = 0.5

_engine = None
_engine_error: str | None = None
_lock = threading.Lock()


def _build_engine():
    """Create an AnalyzerEngine. The lightweight en_core_web_sm model is
    tried FIRST — it's the one the install instructions provide — with the
    Presidio default (large model) as fallback. Guarded against SystemExit:
    spaCy's model auto-downloader calls pip and exits the interpreter on
    failure, which must never take Warden down with it."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    try:
        provider = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        })
        return AnalyzerEngine(nlp_engine=provider.create_engine())
    except (Exception, SystemExit):
        return AnalyzerEngine()


def _get_engine():
    global _engine, _engine_error
    if _engine is not None or _engine_error is not None:
        return _engine
    with _lock:
        if _engine is None and _engine_error is None:
            try:
                _engine = _build_engine()
            except (Exception, SystemExit) as e:  # ImportError, model download exit
                _engine_error = repr(e)
    return _engine


def available() -> tuple[bool, str | None]:
    """(True, None) if the backend can load; (False, why) otherwise.
    Called by policy validation so a policy that demands presidio fails
    loudly at startup when the dependency is absent."""
    eng = _get_engine()
    return (eng is not None), _engine_error


def scan_presidio(text: str, entities: list[str] | None = None,
                  min_score: float = DEFAULT_MIN_SCORE) -> "list[Finding]":
    """Run Presidio over text and return findings in the SAME Finding shape
    the regex detectors produce, so redact()/policy code needs no changes.
    Detector names are namespaced: presidio_email_address, presidio_us_ssn…
    """
    from proxy.inspect.redactor import Finding

    if not text:
        return []
    eng = _get_engine()
    if eng is None:
        # Defensive: policy validation should have refused this configuration
        # already. Fail closed rather than silently returning nothing.
        raise RuntimeError(
            f"presidio detector enabled but backend unavailable: {_engine_error}")

    results = eng.analyze(text=text, language="en",
                          entities=entities or DEFAULT_ENTITIES)
    findings = []
    for r in results:
        if r.score < min_score:
            continue
        findings.append(Finding(
            detector=f"presidio_{r.entity_type.lower()}",
            match=text[r.start:r.end],
            start=r.start,
            end=r.end,
        ))
    return findings
