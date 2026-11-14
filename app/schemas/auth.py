import uuid
from datetime import datetime
import re
from pydantic import BaseModel, EmailStr, field_validator


class SignupRequest(BaseModel):
    name: str                  # min 2, max 100 chars
    username: str              # min 3, max 30, only alphanumeric + underscore
    email: EmailStr
    password: str              # min 8, must have uppercase + number + special char

    @field_validator("name")
    def name_length(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2 or len(v) > 100:
            raise ValueError("Name must be between 2 and 100 characters")
        return v

    @field_validator("username")
    def username_format(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', v):
            raise ValueError("Username must be 3-30 chars, alphanumeric and underscores only")
        return v.lower()

    @field_validator("password")
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain an uppercase letter")
        if not re.search(r'\d', v):
            raise ValueError("Password must contain a number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain a special character")
        return v


class OTPVerifyRequest(BaseModel):
    email: EmailStr
    otp: str                   # exactly 6 digits

    @field_validator("otp")
    def otp_format(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r'^\d{6}$', v):
            raise ValueError("OTP must be exactly 6 digits")
        return v


class ResendOTPRequest(BaseModel):
    email: EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UsernameSetRequest(BaseModel):
    username: str
    temp_token: str

    @field_validator("username")
    def username_format(cls, v: str) -> str:
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', v):
            raise ValueError("Invalid username format")
        return v.lower()


class UserPublic(BaseModel):
    id: uuid.UUID
    name: str
    username: str
    email: str
    email_verified: bool
    bio: str | None = ""
    avatar_url: str | None = None
    created_at: datetime
    xp: int = 0
    tier: str = "Stowaway"

    model_config = {"from_attributes": True}


class UserUpdateRequest(BaseModel):
    name: str | None = None
    bio: str | None = None
    avatar_url: str | None = None

    @field_validator("name")
    def name_length(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.strip()
            if len(v) < 2 or len(v) > 100:
                raise ValueError("Name must be between 2 and 100 characters")
        return v

    @field_validator("bio")
    def bio_length(cls, v: str | None) -> str | None:
        if v is not None and len(v) > 255:
            raise ValueError("Bio must be at most 255 characters")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic
    message: str | None = None