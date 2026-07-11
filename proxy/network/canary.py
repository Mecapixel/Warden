"""
proxy/network/canary.py  (v3)

Canary tokens — the zero-false-positive exfiltration tripwire.

Every other detector in Warden reasons about what traffic MIGHT be; a canary
is different in kind. Warden mints unique markers that exist nowhere in the
world except decoy files it plants in the session workspace. Those markers
have exactly one way to appear in an outbound tool call: something read the
decoy and is moving its contents off the machine. There is no benign
explanation, so a canary hit is a CONFIRMED exfiltration signal (rule
CAN-001, risk 100) — the only detector in the system permitted to claim
certainty, because its false-positive cost is structurally zero.

Decoys are dressed as the files an exfiltrating agent is steered toward
first: a .env with fake credentials, an SSH-key-shaped file, a notes file.
The fake values embed the marker so partial exfiltration (grepping just the
"AWS key" line) still trips the wire.

The vault persists to JSON so markers planted in one session are still
recognized in the next — an agent that stashes a canary in long-term memory
and exfiltrates it tomorrow is exactly the patient adversary this defends
against.
"""

import json
import secrets
from pathlib import Path

_PREFIX = "WRDN"  # marker shape: WRDN-CANARY-<24 hex chars>


class CanaryVault:
    def __init__(self, store_path: str | None = None):
        self._tokens: dict[str, str] = {}   # token -> label
        self._path = Path(store_path) if store_path else None
        if self._path and self._path.exists():
            self._load()

    # ------------------------------------------------------------------ #
    def mint(self, label: str) -> str:
        token = f"{_PREFIX}-CANARY-{secrets.token_hex(12)}"
        self._tokens[token] = label
        self._save()
        return token

    def scan(self, text: str) -> list[tuple[str, str]]:
        """Return [(token, label)] for every registered marker in text.

        Substring scan, deliberately: encodings that survive JSON transport
        (the marker inside a URL, a header value, a message body) all still
        contain the literal token. Base64-wrapped payloads are handled
        upstream by the download/args pipeline that decodes before scanning.
        """
        if not self._tokens or not text:
            return []
        return [(t, lbl) for t, lbl in self._tokens.items() if t in text]

    @property
    def count(self) -> int:
        return len(self._tokens)

    # ------------------------------------------------------------------ #
    def seed_workspace(self, workspace_root: str) -> list[str]:
        """Plant decoy files bearing fresh markers. Returns paths written.

        Each decoy is labeled by its lure type so the audit record of a hit
        names WHICH decoy was taken — that is forensic information about
        what the agent was steered to read.
        """
        root = Path(workspace_root)
        root.mkdir(parents=True, exist_ok=True)
        written: list[str] = []

        t_env = self.mint("decoy:.env")
        p = root / ".env"
        p.write_text(
            "# service configuration — do not commit\n"
            f"AWS_ACCESS_KEY_ID=AKIA{t_env[-16:].upper()}\n"
            f"AWS_SECRET_ACCESS_KEY={t_env}\n"
            f"DATABASE_URL=postgres://svc:{t_env}@db.internal:5432/prod\n"
        )
        written.append(str(p))

        t_key = self.mint("decoy:ssh_key")
        p = root / "id_ed25519_backup"
        p.write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{t_key}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        written.append(str(p))

        t_note = self.mint("decoy:notes")
        p = root / "passwords_old.txt"
        p.write_text(
            "reminder: rotate these\n"
            f"vpn admin portal: {t_note}\n"
        )
        written.append(str(p))

        return written

    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text())
            self._tokens = {t: str(lbl) for t, lbl in raw.items()
                            if isinstance(t, str) and t.startswith(f"{_PREFIX}-CANARY-")}
        except Exception:
            self._tokens = {}

    def _save(self) -> None:
        if not self._path:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._tokens, indent=1, sort_keys=True))
        except Exception:
            pass  # persistence failure must not break minting or scanning
