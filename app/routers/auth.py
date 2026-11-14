from datetime import datetime, timezone
import logging
import secrets
import urllib
import urllib.parse
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.core.config import settings
from app.schemas.auth import (
    SignupRequest,
    OTPVerifyRequest,
    ResendOTPRequest,
    LoginRequest,
    UsernameSetRequest,
    TokenResponse,
    UserPublic,
    UserUpdateRequest,
)
from app.services import auth_service, oauth_service, rank_service
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_temp_token,
    decode_token,
)

from app.core.dependencies import get_verified_user
from app.models.users import User

logger = logging.getLogger(__name__)
router = APIRouter()


def _user_with_xp(db: Session, user: User) -> UserPublic:
    data = UserPublic.model_validate(user)
    try:
        xp = rank_service.get_user_xp(db, user.id)
        data.xp = xp
        tiers = rank_service.get_all_tiers(db)
        current_tier, _ = rank_service.calculate_rank_for_xp(tiers, xp)
        if rank_service.is_user_mythical(db, user.id):
            data.tier = "??? (Pirate King)"
        elif current_tier:
            data.tier = current_tier.name
    except Exception as e:
        logger.warning(f"Could not compute rank/xp for user {user.id}: {e}")
    return data


# ─── Manual Signup ────────────────────────────────────────────────────────────

@router.post("/signup", status_code=201)
def signup(body: SignupRequest, db: Session = Depends(get_db)):
    if auth_service.check_username_taken(db, body.username):
        raise HTTPException(status_code=400, detail="Username already taken")
    if auth_service.check_email_taken(db, body.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    user = auth_service.create_user(
        db,
        name=body.name,
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
    )
    auth_service.set_and_send_otp(db, user)
    return {"message": "Account created. Check your email for a verification code."}


# ─── Verify Email ─────────────────────────────────────────────────────────────

@router.post("/verify-email", response_model=TokenResponse)
def verify_email(body: OTPVerifyRequest, db: Session = Depends(get_db)):
    error_map = {
        "USER_NOT_FOUND": (404, "User not found"),
        "ALREADY_VERIFIED": (400, "Email already verified"),
        "TOO_MANY_ATTEMPTS": (429, "Too many attempts. Request a new OTP."),
        "NO_OTP": (400, "No OTP found. Please request a new one."),
        "OTP_EXPIRED": (400, "OTP has expired. Please request a new one."),
        "INVALID_OTP": (400, "Invalid OTP."),
    }
    try:
        user = auth_service.verify_user_otp(db, body.email, body.otp)
    except ValueError as e:
        code, msg = error_map.get(str(e), (400, "Verification failed"))
        raise HTTPException(status_code=code, detail=msg)

    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer", "user": _user_with_xp(db, user)}


# ─── Resend OTP ───────────────────────────────────────────────────────────────

@router.post("/resend-otp")
def resend_otp(body: ResendOTPRequest, db: Session = Depends(get_db)):
    error_map = {
        "USER_NOT_FOUND": (404, "User not found"),
        "ALREADY_VERIFIED": (400, "Email already verified"),
        "RESEND_TOO_SOON": (429, "Please wait at least 2 minutes before requesting a new code."),
    }
    try:
        auth_service.resend_otp_for_user(db, body.email)
    except ValueError as e:
        code, msg = error_map.get(str(e), (400, "Failed to resend OTP"))
        raise HTTPException(status_code=code, detail=msg)
    return {"message": "Verification code resent."}


# ─── Username Availability Check ──────────────────────────────────────────────

@router.get("/check-username")
def check_username(username: str, db: Session = Depends(get_db)):
    taken = auth_service.check_username_taken(db, username.lower())
    return {"available": not taken}


# ─── Login ────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email.lower()).first()

    # Always return the same error — prevents email enumeration
    if not user or not user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.email_verified:
        raise HTTPException(status_code=403, detail="Please verify your email before logging in.")

    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer", "user": _user_with_xp(db, user)}


# ─── Google OAuth ─────────────────────────────────────────────────────────────

@router.get("/google")
def google_login(request: Request, frontend_url: str | None = None):
    state = secrets.token_urlsafe(16)
    url = oauth_service.get_google_auth_url(state)
    # Store state in a short-lived signed cookie for CSRF protection
    response = RedirectResponse(url)
    response.set_cookie("oauth_state", state, max_age=300, httponly=True, samesite="lax")

    # Capture the frontend URL so the callback redirects to the exact frontend port/origin
    target = frontend_url or request.headers.get("referer") or settings.FRONTEND_URL
    if target:
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme and parsed.netloc:
            clean_origin = f"{parsed.scheme}://{parsed.netloc}"
            response.set_cookie("oauth_frontend_url", clean_origin, max_age=300, httponly=True, samesite="lax")
    return response


@router.head("/google", include_in_schema=False)
def google_login_head(request: Request, frontend_url: str | None = None):
    return google_login(request, frontend_url)


@router.get("/google/callback")
async def google_callback(code: str, state: str, request: Request, db: Session = Depends(get_db)):
    # Determine the frontend redirect target
    frontend_origin = (
        request.cookies.get("oauth_frontend_url")
        or request.headers.get("referer")
        or settings.FRONTEND_URL
    ).rstrip("/")
    if frontend_origin:
        parsed = urllib.parse.urlparse(frontend_origin)
        if parsed.scheme and parsed.netloc:
            frontend_origin = f"{parsed.scheme}://{parsed.netloc}"
    frontend_callback_url = f"{frontend_origin}/auth/google/callback"

    # CSRF check
    stored_state = request.cookies.get("oauth_state")
    if not stored_state or stored_state != state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state. Possible CSRF attack.")

    try:
        profile = await oauth_service.exchange_code_for_profile(code)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during Google OAuth callback: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail="Failed to authenticate with Google.")

    google_id = profile["google_id"]
    email = profile["email"].lower()
    name = profile["name"]

    wants_json = request.query_params.get("format") == "json" or (
        request.headers.get("accept") == "application/json"
        and "text/html" not in request.headers.get("accept", "")
    )

    # Case 1: Google account already linked — log in directly
    existing_by_google = db.query(User).filter(User.google_id == google_id).first()
    if existing_by_google:
        if not existing_by_google.email_verified:
            existing_by_google.email_verified = True
            existing_by_google.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(existing_by_google)
        token = create_access_token({"sub": str(existing_by_google.id)})
        if wants_json:
            return {"access_token": token, "token_type": "bearer", "user": _user_with_xp(db, existing_by_google)}
        redir = RedirectResponse(f"{frontend_callback_url}?token={token}&access_token={token}")
        redir.delete_cookie("oauth_state")
        redir.delete_cookie("oauth_frontend_url")
        return redir

    # Case 2: Email exists but no Google link — link accounts and auto-verify
    existing_by_email = db.query(User).filter(User.email == email).first()
    if existing_by_email:
        existing_by_email.google_id = google_id
        existing_by_email.email_verified = True
        existing_by_email.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(existing_by_email)
        token = create_access_token({"sub": str(existing_by_email.id)})
        if wants_json:
            return {"access_token": token, "token_type": "bearer", "user": _user_with_xp(db, existing_by_email)}
        redir = RedirectResponse(f"{frontend_callback_url}?token={token}&access_token={token}")
        redir.delete_cookie("oauth_state")
        redir.delete_cookie("oauth_frontend_url")
        return redir

    # Case 3: Brand new user — create account, ask for username
    # We don't know their username yet, so create a temp token
    temp_token = create_temp_token({"google_id": google_id, "email": email, "name": name})
    if wants_json:
        return {
            "requires_username": True,
            "temp_token": temp_token,
            "message": "Please choose a username to complete signup.",
        }
    redir = RedirectResponse(
        f"{frontend_callback_url}?requires_username=true&temp_token={urllib.parse.quote(temp_token)}&email={urllib.parse.quote(email)}"
    )
    redir.delete_cookie("oauth_state")
    redir.delete_cookie("oauth_frontend_url")
    return redir


@router.post("/google/set-username", response_model=TokenResponse, status_code=201)
def google_set_username(body: UsernameSetRequest, db: Session = Depends(get_db)):
    payload = decode_token(body.temp_token)
    if not payload or payload.get("type") != "temp":
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    email = payload.get("email")
    google_id = payload.get("google_id")
    name = payload.get("name")

    if auth_service.check_username_taken(db, body.username):
        raise HTTPException(status_code=400, detail="Username already taken.")

    # Create the user already verified via Google OAuth
    user = auth_service.create_user(
        db,
        name=name,
        username=body.username,
        email=email,
        google_id=google_id,
    )
    user.email_verified = True
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": str(user.id)})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _user_with_xp(db, user),
        "message": "Account created successfully.",
    }


# ─── Current User / Profile ───────────────────────────────────────────────────

@router.get("/me", response_model=UserPublic)
def get_me(db: Session = Depends(get_db), current_user: User = Depends(get_verified_user)):
    return _user_with_xp(db, current_user)


@router.patch("/me", response_model=UserPublic)
def update_me(
    payload: UserUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_verified_user),
):
    """Update profile fields (name, bio, avatar_url) for authenticated user."""
    if payload.name is not None:
        current_user.name = payload.name
    if payload.bio is not None:
        current_user.bio = payload.bio
    if payload.avatar_url is not None:
        current_user.avatar_url = payload.avatar_url
    db.commit()
    db.refresh(current_user)
    return _user_with_xp(db, current_user)