import logging
import urllib.parse
import httpx
from fastapi import HTTPException
from app.core.config import settings

logger = logging.getLogger(__name__)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"


def _get_clean_redirect_uri() -> str:
    uri = settings.GOOGLE_REDIRECT_URI.strip()
    # Automatically clean up accidental double schemes (e.g. https://https://)
    while uri.startswith("https://https://"):
        uri = uri[8:]
    while uri.startswith("http://http://"):
        uri = uri[7:]
    # Clean accidental duplicated callback paths
    if "/auth/google/callback/auth/google/callback" in uri:
        uri = uri.replace("/auth/google/callback/auth/google/callback", "/auth/google/callback")
    return uri


def get_google_auth_url(state: str) -> str:
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID.strip(),
        "redirect_uri": _get_clean_redirect_uri(),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    query = urllib.parse.urlencode(params)
    return f"{GOOGLE_AUTH_URL}?{query}"


async def exchange_code_for_profile(code: str) -> dict:
    redirect_uri = _get_clean_redirect_uri()
    async with httpx.AsyncClient() as client:
        # Step 1: exchange code for tokens
        token_res = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID.strip(),
                "client_secret": settings.GOOGLE_CLIENT_SECRET.strip(),
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        if token_res.status_code != 200:
            error_detail = token_res.text
            try:
                err_data = token_res.json()
                error_detail = err_data.get("error_description") or err_data.get("error") or token_res.text
            except Exception:
                pass
            logger.error(
                f"Google OAuth token exchange failed with status {token_res.status_code}. "
                f"redirect_uri used: {redirect_uri}. Google response: {token_res.text}"
            )
            # Friendly explanation for common Google OAuth errors
            err_lower = error_detail.lower()
            if "invalid_grant" in err_lower:
                detail = "Google authorization code expired or was already used. Please try logging in again."
            elif "redirect_uri_mismatch" in err_lower:
                detail = f"Redirect URI mismatch. Google received '{redirect_uri}' which does not match Google Console."
            elif "invalid_client" in err_lower:
                detail = "Invalid Google OAuth client credentials. Check GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET on Render."
            else:
                detail = f"Failed to authenticate with Google: {error_detail}"
            raise HTTPException(status_code=400, detail=detail)

        access_token = token_res.json()["access_token"]

        # Step 2: fetch user profile
        profile_res = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if profile_res.status_code != 200:
            logger.error(f"Google UserInfo request failed: {profile_res.text}")
            raise HTTPException(status_code=400, detail="Failed to fetch Google user profile.")

        data = profile_res.json()

    return {
        "google_id": data["sub"],
        "email": data["email"],
        "name": data.get("name", ""),
    }
