import re
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

shared_config = ConfigDict(from_attributes=True, populate_by_name=True)


class Gender(str, Enum):
    MALE = "MALE"
    FEMALE = "FEMALE"


class Role(str, Enum):
    ADMIN = "ADMIN"
    USER = "USER"


class MaritalStatus(str, Enum):
    SINGLE = "SINGLE"
    MARRIED = "MARRIED"
    DIVORCED = "DIVORCED"
    WIDOWED = "WIDOWED"


class UserCreate(BaseModel):
    email: EmailStr = Field(..., max_length=254, alias="email")
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


class AdminCreate(UserCreate):
    role: Role


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
    role: Role
    is_active: bool = Field(..., alias="isActive")
    created_at: datetime = Field(..., alias="createdAt")
    updated_at: datetime = Field(..., alias="updatedAt")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class AuthResponse(BaseModel):
    access_token: str = Field(..., alias="accessToken")
    expires_in: int = Field(3600, alias="expiresIn")
    user: UserResponse


class UserUpdate(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=200, alias="fullName")
    age: Optional[int] = Field(..., ge=18, le=120)
    region: Optional[str] = Field(..., max_length=32)
    gender: Optional[Gender] = Field(...)
    marital_status: Optional[MaritalStatus] = Field(..., alias="maritalStatus")

    model_config = shared_config


# 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000


class FraudRuleBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=120)
    description: Optional[str] = Field(None, max_length=500)
    dsl_expression: str = Field(
        ..., min_length=3, max_length=2000, alias="dslExpression"
    )
    enabled: bool = Field(True)
    priority: int = Field(100, ge=1)

    model_config = ConfigDict(populate_by_name=True, from_attributes=True)


class FraudRuleCreate(FraudRuleBase):
    pass


class FraudRuleUpdate(BaseModel):
    name: str = Field(..., min_length=3, max_length=120)
    description: Optional[str] = Field(..., max_length=500)
    dsl_expression: str = Field(
        ..., min_length=3, max_length=2000, alias="dslExpression"
    )
    enabled: bool = Field(...)
    priority: int = Field(..., ge=1)

    model_config = ConfigDict(populate_by_name=True)


class FraudRuleResponse(FraudRuleBase):
    id: UUID
    created_at: datetime = Field(..., alias="createdAt")
    updated_at: datetime = Field(..., alias="updatedAt")
