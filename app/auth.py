"""Authentification : mot de passe haché (scrypt, stdlib), sessions par cookie, et limitation
des tentatives (anti-force-brute) commune à la page de connexion, à l'auth Basic et à la biométrie.

Le mot de passe n'est jamais stocké en clair : seule son empreinte scrypt est gardée en base
(table meta). Les jetons de session ne sont pas stockés non plus : la base n'en garde que le
SHA-256, si bien qu'une copie de la base ne permet pas de reprendre une session.
`NETWATCH_PASSWORD` sert uniquement à l'amorçage au premier démarrage ; ensuite le mot de passe
se change dans l'interface. L'auth Basic reste acceptée pour les scripts/API.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import time

log = logging.getLogger("netwatch.auth")

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**16, 8, 1
SCRYPT_MAXMEM = 256 * 1024 * 1024
MAX_PASSWORD_LEN = 1024     # au-delà : refus (évite de hacher des mégaoctets)
LOGIN_WINDOW = 300          # fenêtre de comptage des échecs (s)
LOGIN_MAX_FAILS = 5         # échecs tolérés par IP dans la fenêtre
LOGIN_LOCK = 300            # blocage après trop d'échecs (s)
GLOBAL_MAX_FAILS = 40       # échecs toutes IP confondues dans la fenêtre : toutes les connexions sont gelées
MAX_TRACKED_IPS = 5000      # borne la mémoire du compteur d'échecs
BASIC_CACHE_TTL = 300       # une auth Basic réussie n'est pas re-hachée à chaque requête


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ------------------------------------------------------------------ hachage
def hash_password(pw: str, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=SCRYPT_MAXMEM)
    return f"scrypt${n}${r}${p}${salt.hex()}${dk.hex()}"


def verify_password(pw: str, stored: str | None) -> bool:
    if not stored or len(pw or "") > MAX_PASSWORD_LEN:
        return False
    try:
        algo, n, r, p, salt_hex, hash_hex = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt_hex),
                            n=int(n), r=int(r), p=int(p), dklen=len(hash_hex) // 2,
                            maxmem=SCRYPT_MAXMEM)
        return secrets.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def needs_rehash(stored: str | None) -> bool:
    """Empreinte calculée avec des paramètres plus faibles que ceux d'aujourd'hui."""
    try:
        _algo, n, r, p, *_ = (stored or "").split("$")
        return (int(n), int(r), int(p)) != (SCRYPT_N, SCRYPT_R, SCRYPT_P)
    except ValueError:
        return False


# ------------------------------------------------------------------ gestionnaire
class Auth:
    def __init__(self, cfg, db):
        self.cfg = cfg
        self.db = db
        self.session_ttl = max(1, cfg.session_days) * 86400
        self._fails: dict[str, list[float]] = {}
        self._locked: dict[str, float] = {}
        self._all_fails: list[float] = []
        self._basic_ok: dict[str, float] = {}       # empreinte de l'en-tête Basic -> expiration
        self._basic_key = secrets.token_bytes(32)
        self._bootstrap()
        self._hash_stored_sessions()

    def _hash_stored_sessions(self) -> None:
        """Les anciennes versions stockaient le jeton de session en clair : on ne garde que son empreinte."""
        for r in self.db.q("SELECT token FROM sessions"):
            if len(r["token"]) != 64:
                self.db.x("UPDATE sessions SET token=? WHERE token=?", [token_hash(r["token"]), r["token"]])

    def _bootstrap(self) -> None:
        stored = self.db.get_meta("auth_hash")
        env = self.cfg.password
        if env and (not stored or self.cfg.password_reset):
            self.db.set_meta("auth_hash", hash_password(env))
            self.db.set_meta("auth_user", self.cfg.username)
            if stored and self.cfg.password_reset:
                log.warning("Mot de passe réinitialisé depuis NETWATCH_PASSWORD (PASSWORD_RESET).")
            else:
                log.warning(
                    "Mot de passe initial défini depuis NETWATCH_PASSWORD. Tu peux le changer "
                    "dans l'interface, puis retirer NETWATCH_PASSWORD de la configuration.")
        elif env and stored:
            log.info("NETWATCH_PASSWORD ignoré : un mot de passe est déjà défini "
                     "(mets NETWATCH_PASSWORD_RESET=true pour le réinitialiser).")
        if self.open_mode:
            log.warning("NETWATCH_NO_AUTH=true : l'interface est ouverte, SANS authentification.")
        elif not self.enabled:
            log.info("Aucun mot de passe défini : un écran de configuration le demandera au premier accès.")

    @property
    def enabled(self) -> bool:
        return bool(self.db.get_meta("auth_hash"))

    @property
    def open_mode(self) -> bool:
        """Interface volontairement sans authentification (NETWATCH_NO_AUTH)."""
        return bool(self.cfg.no_auth)

    @property
    def setup_required(self) -> bool:
        """Aucun mot de passe défini et mode ouvert non demandé : premier démarrage."""
        return not self.enabled and not self.open_mode

    @property
    def username(self) -> str:
        return self.db.get_meta("auth_user") or self.cfg.username

    def initial_setup(self, user: str, pw: str) -> tuple[bool, str | None]:
        """Crée le compte admin au premier démarrage. Refusé si déjà configuré."""
        if self.enabled:
            return False, "authentification déjà configurée"
        user = (user or "").strip()[:64] or self.cfg.username
        if len(pw or "") < 8:
            return False, "le mot de passe doit faire au moins 8 caractères"
        if len(pw) > MAX_PASSWORD_LEN:
            return False, "mot de passe trop long"
        self.db.set_meta("auth_user", user)
        self.db.set_meta("auth_hash", hash_password(pw))
        log.info("Compte administrateur créé via l'écran de configuration (utilisateur : %s)", user)
        return True, None

    # -------------------------------------------------------------- identifiants
    def check_credentials(self, user: str, pw: str) -> bool:
        if not user or not secrets.compare_digest(user.encode(), self.username.encode()):
            # on hache quand même pour ne pas révéler l'existence du compte par le temps de réponse
            verify_password(pw, self.db.get_meta("auth_hash"))
            return False
        stored = self.db.get_meta("auth_hash")
        ok = verify_password(pw, stored)
        if ok and needs_rehash(stored):            # renforce l'empreinte au fil des connexions
            self.db.set_meta("auth_hash", hash_password(pw))
        return ok

    def check_basic(self, header_value: str, user: str, pw: str) -> bool:
        """Auth Basic : même contrôle, mais un succès est mémorisé quelques minutes (scrypt est coûteux)."""
        import hmac
        key = hmac.new(self._basic_key, header_value.encode(), hashlib.sha256).hexdigest()
        now = time.time()
        if self._basic_ok.get(key, 0) > now:
            return True
        if not self.check_credentials(user, pw):
            return False
        if len(self._basic_ok) > 64:
            self._basic_ok = {k: v for k, v in self._basic_ok.items() if v > now}
        self._basic_ok[key] = now + BASIC_CACHE_TTL
        return True

    def set_password(self, current: str, new: str) -> tuple[bool, str | None]:
        if not self.check_credentials(self.username, current):
            return False, "mot de passe actuel incorrect"
        if len(new or "") < 8:
            return False, "le nouveau mot de passe doit faire au moins 8 caractères"
        if len(new) > MAX_PASSWORD_LEN:
            return False, "mot de passe trop long"
        self.db.set_meta("auth_hash", hash_password(new))
        self._basic_ok.clear()
        self._invalidate_all_sessions()
        return True, None

    # -------------------------------------------------------------- sessions
    def create_session(self, ip: str | None) -> tuple[str, int]:
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        expires = now + self.session_ttl
        self.db.x("INSERT INTO sessions(token, username, created, expires, ip) VALUES(?,?,?,?,?)",
                  [token_hash(token), self.username, now, expires, ip])
        return token, expires

    def validate_session(self, token: str | None) -> str | None:
        if not token or len(token) > 256:
            return None
        h = token_hash(token)
        row = self.db.q1("SELECT username, expires FROM sessions WHERE token=?", [h])
        if not row:
            return None
        if row["expires"] < time.time():
            self.db.x("DELETE FROM sessions WHERE token=?", [h])
            return None
        return row["username"]

    def destroy_session(self, token: str | None) -> None:
        if token:
            self.db.x("DELETE FROM sessions WHERE token=?", [token_hash(token)])

    def _invalidate_all_sessions(self) -> None:
        self.db.x("DELETE FROM sessions")

    def purge_sessions(self) -> None:
        self.db.x("DELETE FROM sessions WHERE expires < ?", [int(time.time())])

    # -------------------------------------------------------------- anti-force-brute
    def locked_for(self, ip: str, password: bool = True) -> int:
        now = time.time()
        until = self._locked.get(ip, 0)
        # trop d'échecs toutes adresses confondues (attaque répartie) : les connexions par mot de passe
        # sont gelées ; la biométrie, qui ne se devine pas, reste possible.
        recent = [t for t in self._all_fails if now - t < LOGIN_WINDOW]
        if password and len(recent) >= GLOBAL_MAX_FAILS:
            until = max(until, recent[-GLOBAL_MAX_FAILS] + LOGIN_WINDOW)
        return max(0, int(until - now))

    def record_failure(self, ip: str) -> None:
        now = time.time()
        self._all_fails = [t for t in self._all_fails if now - t < LOGIN_WINDOW][-GLOBAL_MAX_FAILS * 2:] + [now]
        if len(self._fails) > MAX_TRACKED_IPS or len(self._locked) > MAX_TRACKED_IPS:
            self._fails = {k: v for k, v in self._fails.items() if v and now - v[-1] < LOGIN_WINDOW}
            self._locked = {k: v for k, v in self._locked.items() if v > now}
            if len(self._fails) > MAX_TRACKED_IPS:
                self._fails.clear()
        fails = [t for t in self._fails.get(ip, []) if now - t < LOGIN_WINDOW]
        fails.append(now)
        self._fails[ip] = fails
        if len(fails) >= LOGIN_MAX_FAILS:
            self._locked[ip] = now + LOGIN_LOCK
            self._fails[ip] = []
            log.warning("Trop d'échecs de connexion depuis %s : bloqué %d s", ip, LOGIN_LOCK)

    def record_success(self, ip: str) -> None:
        self._fails.pop(ip, None)
        self._locked.pop(ip, None)
