"""Firebase Admin SDK initialization and token verification for iqAudi360."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import firebase_admin
from firebase_admin import auth as firebase_auth, credentials

logger = logging.getLogger(__name__)

_firebase_app: firebase_admin.App | None = None


def get_service_account_path() -> Path:
    """Resolve path to Firebase service account JSON."""
    env_path = os.environ.get("FIREBASE_CREDENTIALS")
    if env_path and Path(env_path).is_file():
        return Path(env_path)

    default_path = Path(__file__).resolve().parent / "firebase_service_account.json"
    if default_path.is_file():
        return default_path

    # Check root workspace path
    root_path = Path.cwd() / "iqaudi360-firebase-adminsdk.json"
    if root_path.is_file():
        return root_path

    return default_path


def init_firebase_admin() -> firebase_admin.App | None:
    """Initialize Firebase Admin SDK with project credentials."""
    global _firebase_app
    if _firebase_app is not None:
        return _firebase_app

    try:
        cred_path = get_service_account_path()
        if not cred_path.is_file():
            logger.warning("Firebase service account credentials file not found at: %s", cred_path)
            return None

        cred = credentials.Certificate(str(cred_path))
        _firebase_app = firebase_admin.initialize_app(cred, name="iqaudi360")
        logger.info("Firebase Admin SDK successfully initialized for project 'iqaudi360'")
        return _firebase_app
    except ValueError:
        # App might already be initialized with default or existing name
        try:
            _firebase_app = firebase_admin.get_app("iqaudi360")
            return _firebase_app
        except Exception as exc:
            logger.error("Failed to retrieve existing Firebase app: %s", exc)
            return None
    except Exception as exc:
        logger.error("Failed to initialize Firebase Admin SDK: %s", exc)
        return None


def verify_id_token(id_token: str) -> dict[str, Any] | None:
    """Verify Firebase ID Token using Firebase Admin SDK.
    
    Returns decoded token dictionary on success, or None on failure.
    """
    app = init_firebase_admin()
    if not app:
        logger.error("Cannot verify token: Firebase Admin SDK not initialized")
        return None

    try:
        decoded = firebase_auth.verify_id_token(id_token, app=app, check_revoked=False)
        return decoded
    except Exception as exc:
        logger.warning("Firebase token verification failed: %s", exc)
        return None


def get_firebase_user(uid: str) -> Any:
    """Fetch Firebase user record by UID."""
    app = init_firebase_admin()
    if not app:
        return None
    try:
        return firebase_auth.get_user(uid, app=app)
    except Exception as exc:
        logger.debug("Firebase get_user failed for UID %s: %s", uid, exc)
        return None


def get_firebase_web_config() -> dict[str, str]:
    """Return public, client-safe Firebase Web SDK configuration.
    
    STRICT SECURITY RULE: Contains ONLY public web identifiers.
    Private keys and service account secrets are NEVER included here.
    """
    return {
        "projectId": "iqaudi360",
        "authDomain": "iqaudi360.firebaseapp.com",
        "storageBucket": "iqaudi360.appspot.com",
        "messagingSenderId": "1091824369139",
    }
