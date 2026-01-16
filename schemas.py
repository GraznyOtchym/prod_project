import re
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class Gender(str, Enum):
    MALE = "MALE"
    FEMALE = "FEMALE"


class MaritalStatus(str, Enum):
    SINGLE = "SINGLE"
    MARRIED = "MARRIED"
    DIVORCED = "DIVORCED"
    WIDOWED = "WIDOWED"


class UserCreate(BaseModel):
    email: EmailStr = Field(..., max_length=254, alias="e-mail")
    password: str = Field(..., min_length=8, max_length=72)
    full_name: str = Field(..., min_length=2, max_length=200, alias="fullName")
    age: Optional[int] = Field(None, ge=18, le=120)
    region: Optional[str] = Field(None, max_length=32)
    gender: Optional[Gender] = None
    marital_status: Optional[MaritalStatus] = Field(None, alias="maritalStatus")

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str):
        if not re.search(r"[A-Za-zА-Яа-я]", v) or not re.search(r"\d", v):
            raise ValueError("password must contain at least one letter and one digit")
        return v


class UserLogin(BaseModel):
    email: EmailStr = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=72)


class UserResponse(BaseModel):
    id: UUID
    email: EmailStr
    full_name: str = Field(..., alias="fullName")
    age: Optional[int] = None
    region: Optional[str] = None
    gender: Optional[Gender] = None
    marital_status: Optional[MaritalStatus] = Field(None, alias="maritalStatus")
    role: str
    is_active: bool = Field(..., alias="isActive")
    created_at: datetime = Field(..., alias="createdAt")
    updated_at: datetime = Field(..., alias="updatedAt")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class AuthResponse(BaseModel):
    access_token: str = Field(..., alias="accessToken")
    expires_in: int = Field(3600, alias="expiresIn")
    user: UserResponse
