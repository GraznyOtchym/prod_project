import re
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)


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


class TransactionChannel(str, Enum):
    WEB = "WEB"
    MOBILE = "MOBILE"
    POS = "POS"
    OTHER = "OTHER"


class TransactionStatus(str, Enum):
    APPROVED = "APPROVED"
    DECLINED = "DECLINED"


shared_config = ConfigDict(from_attributes=True, populate_by_name=True)


class UserCreate(BaseModel):
    email: EmailStr = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=72)
    full_name: str = Field(..., min_length=2, max_length=200, alias="fullName")
    age: int | None = Field(None, ge=18, le=120)
    region: str | None = Field(None, max_length=32)
    gender: Gender | None = None
    marital_status: MaritalStatus | None = Field(None, alias="maritalStatus")

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
    age: int | None = None
    region: str | None = None
    gender: Gender | None = None
    marital_status: MaritalStatus | None = Field(None, alias="maritalStatus")
    role: Role
    is_active: bool = Field(..., alias="isActive")
    created_at: datetime = Field(..., alias="createdAt")
    updated_at: datetime = Field(..., alias="updatedAt")

    model_config = shared_config


class UserUpdate(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=200, alias="fullName")
    age: int | None = Field(None, ge=18, le=120)
    region: str | None = Field(None, max_length=32)
    gender: Gender | None = None
    marital_status: MaritalStatus | None = Field(None, alias="maritalStatus")

    model_config = shared_config


class UserList(BaseModel):
    items: list[UserResponse]
    total: int
    page: int
    size: int


class AuthResponse(BaseModel):
    access_token: str = Field(..., alias="accessToken")
    expires_in: int = Field(3600, alias="expiresIn")
    user: UserResponse


class FraudRuleBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=120)
    description: str | None = Field(None, max_length=500)
    dsl_expression: str = Field(
        ..., min_length=3, max_length=2000, alias="dslExpression"
    )
    enabled: bool = True
    priority: int = Field(100, ge=1, le=1000)

    model_config = shared_config


class FraudRuleCreate(FraudRuleBase):
    pass


class FraudRuleUpdate(BaseModel):
    name: str = Field(..., min_length=3, max_length=120)
    description: str | None = Field(None, max_length=500)
    dsl_expression: str = Field(
        ..., min_length=3, max_length=2000, alias="dslExpression"
    )
    enabled: bool
    priority: int = Field(..., ge=1, le=1000)

    model_config = shared_config


class FraudRuleResponse(FraudRuleBase):
    id: UUID
    created_at: datetime = Field(..., alias="createdAt")
    updated_at: datetime = Field(..., alias="updatedAt")


class DSLValidateRequest(BaseModel):
    dsl_expression: str = Field(..., alias="dslExpression")


class DSLError(BaseModel):
    code: str
    message: str
    position: int | None = None
    near: str | None = None


class DSLValidationResponse(BaseModel):
    is_valid: bool = Field(..., alias="isValid")
    normalized_expression: str | None = Field(None, alias="normalizedExpression")
    errors: list[DSLError] = []


class LocationBase(BaseModel):
    country: str = Field(..., min_length=2, max_length=2, pattern="^[A-Z]{2}$")
    city: str = Field(..., max_length=128)
    latitude: float | None = Field(None, ge=-90, le=90)
    longitude: float | None = Field(None, ge=-180, le=180)

    @model_validator(mode="after")
    def check_lat_lng_pair(self) -> "LocationBase":
        if (self.latitude is None) != (self.longitude is None):
            raise ValueError("latitude and longitude must be provided together")
        return self


class TransactionCreate(BaseModel):
    user_id: UUID | None = Field(None, alias="userId")
    amount: Decimal = Field(..., ge=0.01, le=999999999.99)
    currency: str = Field(..., pattern="^[A-Z]{3}$")
    timestamp: datetime
    merchant_id: str | None = Field(None, max_length=64, alias="merchantId")
    merchant_category_code: str | None = Field(
        None, pattern="^[0-9]{4}$", alias="merchantCategoryCode"
    )
    ip_address: str | None = Field(None, max_length=64, alias="ipAddress")
    device_id: str | None = Field(None, max_length=128, alias="deviceId")
    channel: TransactionChannel | None = None
    location: LocationBase | None = None
    metadata: dict[str, Any] | None = None

    model_config = shared_config


class RuleResultResponse(BaseModel):
    rule_id: UUID = Field(..., alias="ruleId")
    rule_name: str = Field(..., alias="ruleName")
    priority: int
    enabled: bool
    matched: bool
    description: str


class TransactionResponseFields(BaseModel):
    id: UUID
    user_id: UUID = Field(..., alias="userId")
    amount: Decimal
    currency: str
    timestamp: datetime
    merchant_id: str | None = Field(None, alias="merchantId")
    merchant_category_code: str | None = Field(None, alias="merchantCategoryCode")
    ip_address: str | None = Field(None, alias="ipAddress")
    device_id: str | None = Field(None, alias="deviceId")
    channel: TransactionChannel | None = None
    location: LocationBase | None = None
    is_fraud: bool = Field(..., alias="isFraud")
    metadata: dict[str, Any] | None = None
    created_at: datetime = Field(..., alias="createdAt")

    model_config = shared_config


class TransactionCreateResponse(BaseModel):
    transaction: TransactionResponseFields
    rule_results: list[RuleResultResponse] = Field(..., alias="ruleResults")

    model_config = shared_config


class BatchTransactions(BaseModel):
    items: list[TransactionCreate]


class MerchantRiskRow(BaseModel):
    merchantId: str | None
    merchantCategoryCode: str | None
    txCount: int
    gmv: float
    declineRate: float


class StatsOverview(BaseModel):
    from_: datetime = Field(..., alias="from")
    to: datetime
    volume: int
    gmv: float
    approvalRate: float
    declineRate: float
    topRiskMerchants: list[MerchantRiskRow]


class TransactionsTimePoint(BaseModel):
    bucketStart: datetime
    txCount: int
    gmv: float
    approvalRate: float
    declineRate: float


class TransactionsTimeSeries(BaseModel):
    points: list[TransactionsTimePoint]


class RuleMatchRow(BaseModel):
    ruleId: str
    ruleName: str
    matches: int
    uniqueUsers: int
    uniqueMerchants: int
    shareOfDeclines: float


class RuleMatchStats(BaseModel):
    items: list[RuleMatchRow]


class MerchantRiskStats(BaseModel):
    items: list[MerchantRiskRow]


class UserRiskProfile(BaseModel):
    userId: str
    txCount_24h: int
    gmv_24h: float
    distinctDevices_24h: int
    distinctIps_24h: int
    distinctCities_24h: int
    declineRate_30d: float
    lastSeenAt: datetime | None
