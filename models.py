import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    JSON,
    UUID,
    Boolean,
    DateTime,
    Integer,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(254), unique=True, index=True, nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    age: Mapped[int | None] = mapped_column(Integer, nullable=True)
    region: Mapped[str | None] = mapped_column(String(32), nullable=True)
    gender: Mapped[str | None] = mapped_column(nullable=True)
    marital_status: Mapped[str | None] = mapped_column(nullable=True)
    role: Mapped[str] = mapped_column(default="USER")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class FraudRule(Base):
    __tablename__ = "fraud_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    dsl_expression: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    amount: Mapped[Decimal] = mapped_column(Numeric(precision=19, scale=2))
    currency: Mapped[str] = mapped_column(String(3))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    merchant_id: Mapped[str | None] = mapped_column(String(64))
    merchant_category_code: Mapped[str | None] = mapped_column(String(4))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    device_id: Mapped[str | None] = mapped_column(String(128))
    channel: Mapped[str | None] = mapped_column(String(20))

    location: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    extra_metadata: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSON)

    def __repr__(self) -> str:
        return f"<Transaction {self.id} | {self.amount} {self.currency}>"
