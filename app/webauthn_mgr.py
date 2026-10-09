"""Connexion biométrique par passkey (WebAuthn / FIDO2).

L'empreinte ou Face ID reste sur l'appareil : le serveur ne stocke qu'une clé publique.
La biométrie complète le mot de passe (on enregistre un passkey une fois connecté, puis on
se connecte sans mot de passe). WebAuthn exige HTTPS (déjà en place derrière le proxy).

Le `rp_id` (domaine) et l'origine sont déduits de la requête, ou forcés par
NETWATCH_RP_ID / NETWATCH_RP_ORIGIN si l'auto-détection ne convient pas.
"""
from __future__ import annotations

import base64
import logging
import secrets
import time

log = logging.getLogger("netwatch.webauthn")

try:
    import webauthn as wa
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
    _AVAILABLE = True
except ImportError:  # pragma: no cover
    _AVAILABLE = False

CHALLENGE_TTL = 300


class WebAuthnManager:
    def __init__(self, cfg, db):
        self.cfg = cfg
        self.db = db
        self._challenges: dict[str, tuple[bytes, float, str]] = {}  # id -> (challenge, exp, purpose)

    @property
    def available(self) -> bool:
        return _AVAILABLE

    def has_credentials(self) -> bool:
        return bool(self.db.q1("SELECT 1 FROM webauthn_credentials LIMIT 1"))

    # -------------------------------------------------------------- contexte (domaine/origine)
    # On se base sur l'en-tête Origin envoyé par le navigateur (ex. https://host:12025) :
    # c'est la seule source fiable, port inclus. rp_id en est déduit (hôte sans port ni schéma).
    def rp_id(self, origin: str | None) -> str:
        if self.cfg.rp_id:
            return self.cfg.rp_id
        host = (origin or "https://localhost").split("://")[-1].split("/")[0].split(":")[0]
        return host or "localhost"

    def origin(self, origin: str | None) -> str:
        return self.cfg.rp_origin or origin or "https://localhost"

    def rp_name(self) -> str:
        return "NetWatch"

    # -------------------------------------------------------------- défis
    def _new_challenge(self, challenge: bytes, purpose: str) -> str:
        self._purge()
        if len(self._challenges) >= 200:          # route publique : la mémoire reste bornée
            self._challenges.pop(next(iter(self._challenges)))
        cid = secrets.token_urlsafe(16)
        self._challenges[cid] = (challenge, time.time() + CHALLENGE_TTL, purpose)
        return cid

    def _take_challenge(self, cid: str, purpose: str) -> bytes | None:
        self._purge()
        item = self._challenges.get(cid)
        if not item or item[2] != purpose or item[1] < time.time():
            return None
        del self._challenges[cid]  # consommé seulement si valide
        return item[0]

    def _purge(self) -> None:
        now = time.time()
        for k in [k for k, v in self._challenges.items() if v[1] < now]:
            self._challenges.pop(k, None)

    # -------------------------------------------------------------- enregistrement
    def begin_registration(self, username: str, origin: str | None) -> tuple[str, str]:
        existing = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"]))
            for r in self.db.q("SELECT credential_id FROM webauthn_credentials")
        ]
        opts = wa.generate_registration_options(
            rp_id=self.rp_id(origin),
            rp_name=self.rp_name(),
            user_name=username,
            user_display_name=username,
            exclude_credentials=existing,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )
        cid = self._new_challenge(opts.challenge, "register")
        return wa.options_to_json(opts), cid

    def complete_registration(self, credential: str | dict, challenge_id: str, origin: str | None,
                              name: str | None) -> tuple[bool, str | None]:
        challenge = self._take_challenge(challenge_id, "register")
        if not challenge:
            return False, "défi expiré, réessaie"
        try:
            v = wa.verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self.rp_id(origin),
                expected_origin=self.origin(origin),
                require_user_verification=False,
            )
        except Exception as e:  # noqa: BLE001
            log.warning("Enregistrement passkey refusé : %s", e)
            return False, "vérification échouée"
        now = int(time.time())
        self.db.x(
            """INSERT INTO webauthn_credentials(credential_id, public_key, sign_count, name, created)
               VALUES(?,?,?,?,?) ON CONFLICT(credential_id) DO UPDATE SET
                 public_key=excluded.public_key, sign_count=excluded.sign_count""",
            [bytes_to_base64url(v.credential_id), bytes_to_base64url(v.credential_public_key),
             v.sign_count, (name or "Passkey")[:60], now])
        return True, None

    # -------------------------------------------------------------- authentification
    def begin_authentication(self, origin: str | None) -> tuple[str, str] | None:
        creds = self.db.q("SELECT credential_id FROM webauthn_credentials")
        if not creds:
            return None
        allow = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"])) for r in creds]
        opts = wa.generate_authentication_options(
            rp_id=self.rp_id(origin),
            allow_credentials=allow,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        cid = self._new_challenge(opts.challenge, "auth")
        return wa.options_to_json(opts), cid

    def complete_authentication(self, credential: str | dict, challenge_id: str, origin: str | None,
                                raw_id_b64: str) -> bool:
        challenge = self._take_challenge(challenge_id, "auth")
        if not challenge:
            return False
        row = self.db.q1("SELECT * FROM webauthn_credentials WHERE credential_id=?", [raw_id_b64])
        if not row:
            return False
        try:
            v = wa.verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self.rp_id(origin),
                expected_origin=self.origin(origin),
                credential_public_key=base64url_to_bytes(row["public_key"]),
                credential_current_sign_count=row["sign_count"],
                require_user_verification=False,
            )
        except Exception as e:  # noqa: BLE001
            log.warning("Connexion passkey refusée : %s", e)
            return False
        self.db.update("webauthn_credentials", row["id"],
                       {"sign_count": v.new_sign_count, "last_used": int(time.time())})
        return True

    # -------------------------------------------------------------- gestion
    def list(self) -> list[dict]:
        return [
            {"id": r["id"], "name": r["name"], "created": r["created"], "last_used": r["last_used"]}
            for r in self.db.q("SELECT id, name, created, last_used FROM webauthn_credentials ORDER BY id")
        ]

    def delete(self, cred_id: int) -> None:
        self.db.x("DELETE FROM webauthn_credentials WHERE id=?", [cred_id])
