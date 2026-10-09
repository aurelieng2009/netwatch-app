"""Coffre des secrets (identifiants SSH, mot de passe de la box, MQTT, jetons) chiffrés au repos.

Chiffrement : AES-256-GCM (authentifié), un nonce aléatoire de 96 bits par secret. Les jetons
portent le préfixe `v2:`. Les secrets écrits par les anciennes versions (Fernet, AES-128-CBC +
HMAC-SHA256) restent lisibles et sont rechiffrés en AES-256-GCM au démarrage.

La clé vient de NETWATCH_SECRET_KEY (dérivée par scrypt, N=2^16, avec un sel propre à
l'installation) ou, à défaut, d'un fichier DATA_DIR/secret.key généré au premier démarrage
(droits 0600). Dans ce second cas la clé est à côté de la base : le chiffrement ne protège alors
que contre la fuite de la base seule. Les secrets ne sortent jamais par l'API.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import time

from .db import DB

log = logging.getLogger("netwatch.vault")

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:  # pragma: no cover - dépendance obligatoire en production
    Fernet = None  # type: ignore[assignment]
    InvalidToken = InvalidTag = Exception  # type: ignore[assignment,misc]

CHECK_PLAINTEXT = b"netwatch-vault-v1"
V2_PREFIX = "v2:"
V2_AAD = b"netwatch-vault-v2"
V2_SCRYPT_N = 2**16
# clés de la table meta qui contiennent un secret chiffré (rechiffrées lors du passage en v2)
META_SECRETS = ("box_password", "box_token", "bbox_password", "mqtt_password", "ha_token", "ai_key")
AUTH_TYPES = ("password", "key")


class VaultError(Exception):
    pass


def derive_key(secret: str, salt: bytes) -> bytes:
    """Clé Fernet des anciennes versions (lecture seule désormais)."""
    raw = hashlib.scrypt(secret.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return base64.urlsafe_b64encode(raw)


def derive_key_v2(secret: str, salt: bytes) -> bytes:
    """Clé AES-256 dérivée de la phrase secrète (scrypt, ~64 Mo de mémoire par essai)."""
    return hashlib.scrypt(secret.encode(), salt=salt, n=V2_SCRYPT_N, r=8, p=1, dklen=32,
                          maxmem=256 * 1024 * 1024)


def expand_key_v2(key_material: bytes) -> bytes:
    """Clé AES-256 tirée de la clé aléatoire du fichier secret.key (HKDF-SHA256)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=V2_AAD).derive(key_material)


def parse_scope(scope: str | list[str] | None) -> list[str]:
    """Valide une liste de sous-réseaux (CIDR). Lève ValueError si l'un est invalide."""
    if not scope:
        return []
    items = scope if isinstance(scope, list) else scope.replace(";", ",").split(",")
    out = []
    for s in items:
        s = s.strip()
        if s:
            out.append(str(ipaddress.ip_network(s, strict=False)))
    return out


def in_scope(ip: str, scope: list[str]) -> bool:
    """Vide = tout le réseau scanné."""
    if not scope:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n) for n in scope)


class Vault:
    def __init__(self, db: DB, secret: str | None, key_path: str):
        self.db = db
        self.locked = False
        self.reason: str | None = None
        self.key_source = "env" if secret else "file"
        self.aes = None
        if Fernet is None:
            self.locked, self.reason = True, "module cryptography absent"
            self.f = None
            return
        if secret:
            if len(secret) < 16:
                log.warning("NETWATCH_SECRET_KEY fait moins de 16 caractères : choisissez une phrase plus longue.")
            salt_hex = db.get_meta("vault_salt")
            if not salt_hex:
                salt_hex = secrets.token_hex(16)
                db.set_meta("vault_salt", salt_hex)
            salt = bytes.fromhex(salt_hex)
            key = derive_key(secret, salt)
            aes_key = derive_key_v2(secret, salt)
        else:
            key = self._file_key(key_path)
            aes_key = expand_key_v2(key)
        self.f = Fernet(key)
        self.aes = AESGCM(aes_key)
        if not self._check():
            self.locked = True
            self.reason = "clé maître différente de celle utilisée pour chiffrer les identifiants"
            log.error("Coffre verrouillé : %s. Les identifiants enregistrés sont inutilisables.", self.reason)
            return
        self._upgrade_legacy()

    def _check(self) -> bool:
        """Vérifie que la clé est bien celle qui a chiffré la base (témoin v2, sinon témoin historique)."""
        check2, check1 = self.db.get_meta("vault_check2"), self.db.get_meta("vault_check")
        try:
            if check2 is not None:
                return self._decrypt_raw(check2) == CHECK_PLAINTEXT
            if check1 is not None and self.f.decrypt(check1.encode()) != CHECK_PLAINTEXT:
                return False
        except (InvalidToken, InvalidTag, ValueError):
            return False
        self.db.set_meta("vault_check2", self._encrypt_raw(CHECK_PLAINTEXT))
        return True

    def _upgrade_legacy(self) -> None:
        """Rechiffre en AES-256-GCM les secrets écrits par les anciennes versions (Fernet)."""
        n = 0
        for r in self.db.q("SELECT id, secret_enc, passphrase_enc FROM credentials"):
            fields = {c: self._reencrypt(r[c]) for c in ("secret_enc", "passphrase_enc")
                      if r[c] and not r[c].startswith(V2_PREFIX)}
            fields = {c: v for c, v in fields.items() if v}
            if fields:
                self.db.update("credentials", r["id"], fields)
                n += len(fields)
        for key in META_SECRETS:
            tok = self.db.get_meta(key)
            if tok and not tok.startswith(V2_PREFIX):
                new = self._reencrypt(tok)
                if new:
                    self.db.set_meta(key, new)
                    n += 1
        if n:
            log.info("Coffre : %d secret(s) rechiffré(s) en AES-256-GCM.", n)

    def _reencrypt(self, token: str) -> str | None:
        try:
            return self._encrypt_raw(self.f.decrypt(token.encode()))
        except InvalidToken:
            return None                    # illisible : on le laisse tel quel

    def _encrypt_raw(self, data: bytes) -> str:
        nonce = secrets.token_bytes(12)
        return V2_PREFIX + base64.urlsafe_b64encode(nonce + self.aes.encrypt(nonce, data, V2_AAD)).decode()

    def _decrypt_raw(self, token: str) -> bytes:
        blob = base64.urlsafe_b64decode(token[len(V2_PREFIX):].encode())
        return self.aes.decrypt(blob[:12], blob[12:], V2_AAD)

    @staticmethod
    def _file_key(path: str) -> bytes:
        if os.path.exists(path):
            with contextlib.suppress(OSError):
                if os.stat(path).st_mode & 0o077:
                    os.chmod(path, 0o600)          # la clé ne doit être lisible que par NetWatch
            with open(path, "rb") as fh:
                return fh.read().strip()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        key = Fernet.generate_key()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        log.warning(
            "Clé des identifiants générée dans %s. Définissez NETWATCH_SECRET_KEY pour ne pas la "
            "stocker à côté des données.", path,
        )
        return key

    # -------------------------------------------------------------- chiffrement
    def encrypt(self, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        self._require()
        return self._encrypt_raw(value.encode())

    def decrypt(self, token: str | None) -> str | None:
        if not token:
            return None
        self._require()
        try:
            if token.startswith(V2_PREFIX):
                return self._decrypt_raw(token).decode()
            return self.f.decrypt(token.encode()).decode()
        except (InvalidToken, InvalidTag, ValueError) as e:
            raise VaultError("secret indéchiffrable") from e

    def _require(self) -> None:
        if self.locked or self.f is None:
            raise VaultError(self.reason or "coffre verrouillé")

    # -------------------------------------------------------------- CRUD
    def list(self) -> list[dict]:
        rows = self.db.q("SELECT * FROM credentials ORDER BY priority, id")
        return [self.public(r) for r in rows]

    @staticmethod
    def public(r: dict) -> dict:
        """Vue sans secret, pour l'API."""
        return {
            "id": r["id"], "name": r["name"], "username": r["username"], "auth_type": r["auth_type"],
            "port": r["port"], "scope": json.loads(r["scope_json"] or "[]"), "priority": r["priority"],
            "use_sudo": bool(r["use_sudo"]), "enabled": bool(r["enabled"]),
            "has_secret": bool(r["secret_enc"]), "has_passphrase": bool(r["passphrase_enc"]),
            "created": r["created"], "last_success": r["last_success"], "last_failure": r["last_failure"],
            "success_count": r["success_count"], "failure_count": r["failure_count"],
        }

    def validate(self, body: dict, partial: bool = False) -> dict:
        """Contrôle et normalise un formulaire d'identifiant. Lève ValueError avec un message lisible."""
        f: dict = {}
        if "name" in body or not partial:
            name = str(body.get("name") or "").strip()[:80]
            if not name:
                raise ValueError("nom obligatoire")
            f["name"] = name
        if "username" in body or not partial:
            user = str(body.get("username") or "").strip()[:64]
            if not user or any(c in user for c in " \t\n:@/"):
                raise ValueError("nom d'utilisateur invalide")
            f["username"] = user
        if "auth_type" in body or not partial:
            at = body.get("auth_type") or "password"
            if at not in AUTH_TYPES:
                raise ValueError("type d'authentification inconnu")
            f["auth_type"] = at
        if "port" in body or not partial:
            port = int(body.get("port") or 22)
            if not 1 <= port <= 65535:
                raise ValueError("port invalide")
            f["port"] = port
        if "scope" in body or not partial:
            try:
                f["scope_json"] = json.dumps(parse_scope(body.get("scope")))
            except ValueError as e:
                raise ValueError(f"sous-réseau invalide : {e}") from e
        if "priority" in body or not partial:
            f["priority"] = int(body.get("priority") or 100)
        for k in ("use_sudo", "enabled"):
            if k in body or not partial:
                f[k] = int(bool(body.get(k, k == "enabled")))
        # secrets : absents ou vides = inchangés en modification
        secret = body.get("secret")
        if secret:
            if len(secret) > 20000:
                raise ValueError("secret trop long")
            at = f.get("auth_type") or body.get("auth_type")
            if at == "key" and "PRIVATE KEY" not in secret:
                raise ValueError("clé privée attendue (format OpenSSH ou PEM)")
            f["secret_enc"] = self.encrypt(secret)
        elif not partial:
            raise ValueError("mot de passe ou clé privée obligatoire")
        if body.get("passphrase"):
            f["passphrase_enc"] = self.encrypt(body["passphrase"])
        elif body.get("clear_passphrase"):
            f["passphrase_enc"] = None
        return f

    def create(self, body: dict) -> dict:
        f = self.validate(body)
        f["created"] = int(time.time())
        cols = ", ".join(f)
        cid = self.db.x(f"INSERT INTO credentials({cols}) VALUES({', '.join('?' * len(f))})", list(f.values()))
        return self.public(self.db.q1("SELECT * FROM credentials WHERE id=?", [cid]))

    def update(self, cid: int, body: dict) -> dict | None:
        if not self.db.q1("SELECT id FROM credentials WHERE id=?", [cid]):
            return None
        self.db.update("credentials", cid, self.validate(body, partial=True))
        return self.public(self.db.q1("SELECT * FROM credentials WHERE id=?", [cid]))

    def delete(self, cid: int) -> None:
        self.db.x("DELETE FROM credentials WHERE id=?", [cid])
        self.db.x("DELETE FROM ssh_attempts WHERE credential_id=?", [cid])
        self.db.x("UPDATE device_ssh SET credential_id=NULL WHERE credential_id=?", [cid])

    def secrets_for(self, r: dict) -> tuple[str | None, str | None]:
        return self.decrypt(r["secret_enc"]), self.decrypt(r["passphrase_enc"])

    def candidates(self, ip: str, open_ports: set[int] | None) -> list[dict]:
        """Identifiants actifs applicables à cette IP, par priorité, limités aux ports SSH ouverts."""
        out = []
        for r in self.db.q("SELECT * FROM credentials WHERE enabled=1 ORDER BY priority, id"):
            if not in_scope(ip, json.loads(r["scope_json"] or "[]")):
                continue
            if open_ports is not None and r["port"] not in open_ports:
                continue
            out.append(r)
        return out
