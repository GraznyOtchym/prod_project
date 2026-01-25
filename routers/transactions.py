import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from db import get_session
from dependencies import get_current_user
from dsl import evaluate_rule
from models import FraudRule, Transaction, User
from schemas import (
    BatchTransactions,
    Role,
    TransactionCreate,
    TransactionCreateResponse,
    TransactionResponseFields,
    TransactionStatus,
)

router = APIRouter(prefix="/api/v1/transactions", tags=["transactions"])


async def process_single_transaction(
    data: TransactionCreate, user: User, session: AsyncSession
):
    target_user_id = (
        data.user_id if user.role == Role.ADMIN and data.user_id else user.id
    )

    result = await session.execute(select(User).where(User.id == target_user_id))
    target_user = result.scalar_one_or_none()

    if not target_user:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    if not target_user.is_active:
        raise HTTPException(status_code=403, detail="USER_DEACTIVATED")

    now = datetime.now(timezone.utc)

    transaction = Transaction(
        user_id=target_user_id,
        amount=data.amount,
        currency=data.currency,
        timestamp=data.timestamp or now,
        merchant_id=data.merchant_id,
        merchant_category_code=data.merchant_category_code,
        ip_address=data.ip_address,
        device_id=data.device_id,
        channel=data.channel,
        location=data.location.model_dump() if data.location else None,
    )

    rules_result = await session.execute(
        select(FraudRule).where(FraudRule.enabled).order_by(FraudRule.priority.asc())
    )
    active_rules = rules_result.scalars().all()

    rule_results = []
    is_fraud = False

    for rule in active_rules:
        try:
            matched = evaluate_rule(rule.dsl_expression, transaction, target_user)
            desc = "Rule matched" if matched else "Rule did not match"
        except Exception as e:
            matched = False
            desc = f"Evaluation error: {e}"

        if matched:
            is_fraud = True

        rule_results.append(
            {
                "ruleId": str(rule.id),
                "ruleName": rule.name,
                "priority": rule.priority,
                "enabled": rule.enabled,
                "matched": matched,
                "description": desc,
            }
        )

    tx_status = "DECLINED" if is_fraud else "APPROVED"

    transaction.extra_metadata = {
        "status": tx_status,
        "isFraud": is_fraud,
        "ruleResults": rule_results,
        "user_metadata": data.metadata,
        "createdAt": now.isoformat(),
    }

    session.add(transaction)
    return transaction, rule_results


@router.post("", response_model=TransactionCreateResponse, status_code=201)
async def create_transaction(
    data: TransactionCreate,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    tx, results = await process_single_transaction(data, user, session)
    await session.commit()
    await session.refresh(tx)

    return {
        "transaction": {
            **tx.__dict__,
            "id": tx.id,
            "status": tx.extra_metadata["status"],
            "isFraud": tx.extra_metadata["isFraud"],
            "metadata": tx.extra_metadata.get("user_metadata"),
            "createdAt": tx.extra_metadata["createdAt"],
        },
        "ruleResults": results,
    }


@router.get("/{id}")
async def get_transaction_by_id(
    id: uuid.UUID,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    query = select(Transaction).where(Transaction.id == id)

    result = await session.execute(query)
    tx = result.scalar_one_or_none()

    if not tx:
        raise HTTPException(
            status_code=404,
            detail="NOT_FOUND",
        )

    if user.role != Role.ADMIN and tx.user_id != user.id:
        raise HTTPException(status_code=403, detail="FORBIDDEN")

    return {
        "transaction": {
            "id": tx.id,
            "userId": tx.user_id,
            "amount": tx.amount,
            "currency": tx.currency,
            "status": tx.extra_metadata.get("status"),
            "merchantId": tx.merchant_id,
            "merchantCategoryCode": tx.merchant_category_code,
            "timestamp": tx.timestamp,
            "ipAddress": tx.ip_address,
            "deviceId": tx.device_id,
            "channel": tx.channel,
            "location": tx.location,
            "isFraud": tx.extra_metadata.get("isFraud", False),
            "metadata": tx.extra_metadata.get("user_metadata"),
            "createdAt": tx.extra_metadata.get("createdAt"),
        },
        "ruleResults": tx.extra_metadata.get("ruleResults"),
    }


@router.get("", response_model=list[TransactionResponseFields])
async def get_transactions(
    user_id: uuid.UUID | None = Query(None, alias="userId"),
    status: TransactionStatus | None = None,
    is_fraud: bool | None = Query(None, alias="isFraud"),
    date_from: datetime | None = Query(None, alias="from"),
    date_to: datetime | None = Query(None, alias="to"),
    page: int = Query(0, ge=0),
    size: int = Query(20, ge=1, le=100),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    now = datetime.now(timezone.utc)
    if not date_to:
        date_to = now
    if not date_from:
        date_from = date_to - timedelta(days=90)

    if date_from >= date_to or (date_to - date_from) > timedelta(days=90):
        raise HTTPException(
            status_code=422,
            detail={"code": "VALIDATION_FAILED", "message": "Invalid range"},
        )

    query = select(Transaction)

    if user.role != Role.ADMIN:
        query = query.where(Transaction.user_id == user.id)
    elif user_id:
        query = query.where(Transaction.user_id == user_id)

    query = query.where(
        and_(Transaction.timestamp >= date_from, Transaction.timestamp <= date_to)
    )

    if status:
        query = query.where(Transaction.extra_metadata["status"].astext == status.value)
    if is_fraud is not None:
        query = query.where(
            Transaction.extra_metadata["isFraud"].astext
            == ("true" if is_fraud else "false")
        )

    result = await session.execute(
        query.order_by(Transaction.timestamp.desc()).offset(page * size).limit(size)
    )

    return [
        {
            "id": tx.id,
            "userId": tx.user_id,
            "amount": tx.amount,
            "currency": tx.currency,
            "status": tx.extra_metadata.get("status"),
            "merchantId": tx.merchant_id,
            "merchantCategoryCode": tx.merchant_category_code,
            "timestamp": tx.timestamp,
            "ipAddress": tx.ip_address,
            "deviceId": tx.device_id,
            "channel": tx.channel,
            "location": tx.location,
            "isFraud": tx.extra_metadata.get("isFraud", False),
            "metadata": tx.extra_metadata.get("user_metadata"),
            "createdAt": tx.extra_metadata.get("createdAt"),
        }
        for tx in result.scalars().all()
    ]


@router.post("/batch")
async def create_batch(
    data: BatchTransactions,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    response_items = []
    error = False
    success = False

    for index, item_data in enumerate(data.items):
        try:
            tx, results = await process_single_transaction(item_data, user, session)

            transaction_data = {
                "id": str(tx.id),
                "userId": str(tx.user_id),
                "amount": float(tx.amount),
                "currency": tx.currency,
                "timestamp": tx.timestamp.isoformat()
                if hasattr(tx.timestamp, "isoformat")
                else str(tx.timestamp),
                "merchantId": tx.merchant_id,
                "merchantCategoryCode": tx.merchant_category_code,
                "ipAddress": tx.ip_address,
                "deviceId": tx.device_id,
                "channel": tx.channel,
                "location": tx.location,
                # Данные из метадаты вытаскиваем безопасно
                "status": tx.extra_metadata.get("status")
                if tx.extra_metadata
                else "UNKNOWN",
                "isFraud": tx.extra_metadata.get("isFraud", False)
                if tx.extra_metadata
                else False,
                "metadata": tx.extra_metadata.get("user_metadata")
                if tx.extra_metadata
                else {},
                "createdAt": tx.extra_metadata.get("createdAt")
                if tx.extra_metadata
                else datetime.now(timezone.utc).isoformat(),
            }

            response_items.append(
                {
                    "index": index,
                    "decision": {
                        "transaction": transaction_data,
                        "ruleResults": results,
                    },
                }
            )
            success = True

        except Exception as e:
            error = True
            response_items.append(
                {
                    "index": index,
                    "error": {
                        "code": "VALIDATION_FAILED",
                        "message": str(e),
                        "traceId": str(uuid.uuid4()),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "path": "/api/v1/transactions/batch",
                    },
                }
            )

    await session.commit()

    if error and success:
        status_code = 207
    elif success:
        status_code = 201
    else:
        status_code = 422

    return JSONResponse(status_code=status_code, content={"items": response_items})
