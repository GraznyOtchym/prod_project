import uuid
from datetime import datetime, timezone

from authx import AuthX, AuthXConfig, RequestToken
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db import get_session
from dsl import evaluate_rule
from models import FraudRule, Transaction, User
from schemas import (
    Role,
    TransactionCreate,
    TransactionCreateResponse,
)

config = AuthXConfig(
    JWT_SECRET_KEY=settings.random_secret,
    JWT_ALGORITHM="HS256",
    JWT_TOKEN_LOCATION=["headers"],
    JWT_ACCESS_TOKEN_EXPIRES=3600,
)

auth = AuthX(config=config)


async def get_current_user(
    token: RequestToken = Depends(auth.access_token_required),
    session: AsyncSession = Depends(get_session),
):
    user = await session.get(User, uuid.UUID(token.sub))

    if not user:
        raise HTTPException(status_code=404, detail="user is not found")

    if not user.is_active:
        raise HTTPException(status_code=423, detail="user is deactivated")

    return user


async def is_admin(admin: User = Depends(get_current_user)):
    if not admin.role == "ADMIN":
        raise HTTPException(status_code=403, detail="forbidden")

    return admin


router = APIRouter(prefix="/api/v1/transactions", tags=["transactions"])


@router.post("", response_model=TransactionCreateResponse, status_code=201)
async def create_transaction(
    data: TransactionCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    user_id = data.user_id if user.role == Role.ADMIN and data.user_id else user.id

    target_user = await session.get(User, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="user is not found")

    if not target_user.is_active:
        raise HTTPException(status_code=403, detail="user is deactivated")

    now = datetime.now(timezone.utc)

    transaction = Transaction(
        user_id=user_id,
        amount=data.amount,
        currency=data.currency,
        timestamp=data.timestamp,
        merchant_id=data.merchant_id,
        merchant_category_code=data.merchant_category_code,
        ip_address=data.ip_address,
        device_id=data.device_id,
        channel=data.channel,
        location=data.location.model_dump() if data.location else None,
        extra_metadata=data.metadata,
    )

    result = await session.execute(
        select(FraudRule).where(FraudRule.enabled).order_by(FraudRule.priority.asc())
    )
    active_rules = result.scalars().all()

    rule_results = []
    is_fraud = False

    for rule in active_rules:
        matched = await evaluate_rule(rule.dsl_expression, transaction, user)

        if matched:
            is_fraud = True
            description = f"Rule matched: {rule.dsl_expression}"
        else:
            description = f"Rule did not match: {rule.dsl_expression}"

        rule_results.append(
            {
                "ruleId": str(rule.id),
                "ruleName": rule.name,
                "priority": rule.priority,
                "enabled": rule.enabled,
                "matched": matched,
                "description": description,
            }
        )

    status = "DECLINED" if is_fraud else "APPROVED"

    transaction.extra_metadata = {
        "status": status,
        "isFraud": is_fraud,
        "ruleResults": rule_results,
        "createdAt": now.isoformat(),
    }

    session.add(transaction)
    await session.commit()
    await session.refresh(transaction)

    return {
        "transaction": {
            "id": transaction.id,
            "userId": transaction.user_id,
            "amount": transaction.amount,
            "currency": transaction.currency,
            "status": status,
            "merchantId": transaction.merchant_id,
            "merchantCategoryCode": transaction.merchant_category_code,
            "timestamp": transaction.timestamp,
            "ipAddress": transaction.ip_address,
            "deviceId": transaction.device_id,
            "channel": transaction.channel,
            "location": transaction.location,
            "isFraud": is_fraud,
            "metadata": data.metadata,
            "createdAt": now,
        },
        "ruleResults": rule_results,
    }


@router.get("")
async def get_transactions():
    pass


@router.get("/{id}", response_model=TransactionCreateResponse)
async def get_transaction_by_id(
    id: uuid.UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    transaction = await session.get(Transaction, id)

    if not transaction:
        raise HTTPException(status_code=404, detail="transaction is not found")

    if transaction.user_id != user.id and user.role != Role.ADMIN:
        raise HTTPException(status_code=403, detail="forbidden")

    meta = transaction.extra_metadata or {}

    return {
        "transaction": {
            "id": transaction.id,
            "userId": transaction.user_id,
            "amount": transaction.amount,
            "currency": transaction.currency,
            "status": meta.get("status"),
            "merchantId": transaction.merchant_id,
            "merchantCategoryCode": transaction.merchant_category_code,
            "timestamp": transaction.timestamp,
            "ipAddress": transaction.ip_address,
            "deviceId": transaction.device_id,
            "channel": transaction.channel,
            "location": transaction.location,
            "isFraud": meta.get("isFraud"),
            "metadata": meta.get("user_metadata"),
            "createdAt": meta.get("createdAt"),
        },
        "ruleResults": meta.get("ruleResults", []),
    }
