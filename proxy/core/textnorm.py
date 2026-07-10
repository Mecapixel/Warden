"""
proxy/core/textnorm.py

Unicode hardening for the Normalize stage. Runs BEFORE any inspection, because
every downstream detector — injection patterns, secret regexes, tool-name
lookups — can otherwise be evaded with lookalike characters:

    "ignore previous instructions"       (Latin)
    "ignore previous instruct\u200bions" (zero-width space inside)
    "ign\u043ere previous instructions"  (Cyrillic о)

Hardening steps, in order:
  1. NFKC normalization        — folds compatibility forms (fullwidth, ligatures)
  2. Strip invisibles          — zero-width chars, bidi controls, soft hyphens
  3. Homoglyph folding         — common Cyrillic/Greek lookalikes -> Latin

The hardened text is used for INSPECTION AND LOOKUP. Original argument values
are preserved for execution (a file legitimately named with Unicode must still
be creatable); the security property is that no inspector ever sees the
un-hardened form.
"""

import unicodedata

# Zero-width and bidirectional control characters used to hide or reorder text.
_INVISIBLES = {
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",          # zero-width
    "\u00ad",                                                    # soft hyphen
    "\u200e", "\u200f",                                          # LRM / RLM
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",            # bidi embed/override
    "\u2066", "\u2067", "\u2068", "\u2069",                      # bidi isolates
}

# Common single-character confusables: Cyrillic and Greek letters visually
# identical to Latin. Deliberately conservative — only unambiguous lookalikes.
_HOMOGLYPHS = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K",
    "\u041c": "M", "\u041d": "H", "\u041e": "O", "\u0420": "P",
    "\u0421": "C", "\u0422": "T", "\u0425": "X",
    "\u03bf": "o", "\u03b1": "a", "\u0391": "A", "\u0392": "B",
    "\u0395": "E", "\u0397": "H", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
    "\u03a7": "X",
})


def harden(text: str) -> str:
    """Return the inspection-safe form of text. Idempotent."""
    if not text:
        return text
    out = unicodedata.normalize("NFKC", text)
    out = "".join(ch for ch in out if ch not in _INVISIBLES)
    # Drop remaining non-printable control/format characters (keep \n \t \r).
    out = "".join(
        ch for ch in out
        if ch in "\n\t\r" or unicodedata.category(ch) not in ("Cf", "Cc")
    )
    return out.translate(_HOMOGLYPHS)


def was_obfuscated(original: str, hardened: str) -> bool:
    """True if hardening changed the text — itself a weak suspicion signal."""
    return original != hardened
