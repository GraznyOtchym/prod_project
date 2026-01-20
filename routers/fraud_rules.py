import uuid

from authx import AuthX, AuthXConfig, RequestToken
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db import get_session
from models import FraudRule, User
from schemas import (
    FraudRuleCreate,
    FraudRuleResponse,
    FraudRuleUpdate,
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


router = APIRouter(
    prefix="/api/v1/fraud-rules", tags=["fraud-rules"], dependencies=[Depends(is_admin)]
)


@router.post("", status_code=201, response_model=FraudRuleResponse)
async def create_fraud_rule(
    data: FraudRuleCreate,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(FraudRule).where(FraudRule.name == data.name))
    check_rule = result.scalars().first()

    if check_rule:
        raise HTTPException(status_code=409, detail="rule is occupied")

    new_rule = FraudRule(
        name=data.name,
        description=data.description,
        dsl_expression=data.dsl_expression,
        enabled=data.enabled,
        priority=data.priority,
    )

    session.add(new_rule)
    await session.commit()
    await session.refresh(new_rule)

    return new_rule


@router.get("")
async def get_fraud_rules(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(FraudRule))
    rules = result.scalars().all()

    return rules


@router.get("/{id}", response_model=FraudRuleResponse)
async def get_fraud_rule_by_id(
    id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    rule = await session.get(FraudRule, id)

    if not rule:
        raise HTTPException(status_code=404, detail="rule is not found")

    return rule


@router.put("/{id}", response_model=FraudRuleResponse)
async def update_fraud_rule(
    id: uuid.UUID,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json")

    rule_to_update = await session.get(FraudRule, id)
    if not rule_to_update:
        raise HTTPException(status_code=404, detail="rule is not found")

    try:
        data = FraudRuleUpdate(**body)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    rule_to_update.name = data.name
    rule_to_update.description = data.description
    rule_to_update.dsl_expression = data.dsl_expression
    rule_to_update.enabled = data.enabled
    rule_to_update.priority = data.priority

    await session.commit()
    await session.refresh(rule_to_update)

    return rule_to_update


@router.delete("/{id}", status_code=204)
async def deactivate_fraud_rule(
    id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    rule = await session.get(FraudRule, id)

    if not rule:
        raise HTTPException(status_code=404, detail="rule is not found")

    if rule.enabled:
        rule.enabled = False
        await session.commit()

    return JSONResponse(status_code=204, content=None)


@router.post("/validate")
async def validate_rule_stub():
    raise HTTPException(status_code=422, detail="DSL_UNSUPPORTED_TIER")
