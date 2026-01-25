import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db import get_session
from dependencies import is_admin
from dsl import validate_rule
from models import FraudRule
from schemas import (
    DSLError,
    DSLValidateRequest,
    DSLValidationResponse,
    FraudRuleCreate,
    FraudRuleResponse,
    FraudRuleUpdate,
)

router = APIRouter(
    prefix="/api/v1/fraud-rules", tags=["fraud-rules"], dependencies=[Depends(is_admin)]
)


@router.post("", status_code=201, response_model=FraudRuleResponse)
async def create_fraud_rule(
    data: FraudRuleCreate,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(FraudRule).where(FraudRule.name == data.name))
    if result.scalars().first():
        raise HTTPException(status_code=409, detail="RULE_ALREADY_EXISTS")

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


@router.get("", response_model=List[FraudRuleResponse])
async def get_fraud_rules(session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(FraudRule).order_by(FraudRule.priority.asc()))
    return result.scalars().all()


@router.get("/{id}", response_model=FraudRuleResponse)
async def get_fraud_rule_by_id(
    id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    rule = await session.get(FraudRule, id)
    if not rule:
        raise HTTPException(status_code=404, detail="RULE_NOT_FOUND")
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
        raise HTTPException(status_code=400, detail="INVALID_JSON")

    rule = await session.get(FraudRule, id)
    if not rule:
        raise HTTPException(status_code=404, detail="RULE_NOT_FOUND")

    try:
        data = FraudRuleUpdate(**body)
    except ValidationError:
        raise HTTPException(status_code=422, detail="VALIDATION_FAILED")

    rule.name = data.name
    rule.description = data.description
    rule.dsl_expression = data.dsl_expression
    rule.enabled = data.enabled
    rule.priority = data.priority

    await session.commit()
    await session.refresh(rule)
    return rule


@router.delete("/{id}", status_code=204)
async def deactivate_fraud_rule(
    id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
):
    rule = await session.get(FraudRule, id)
    if not rule:
        raise HTTPException(status_code=404, detail="RULE_NOT_FOUND")

    rule.enabled = False
    await session.commit()
    return None


@router.post("/validate", response_model=DSLValidationResponse)
async def validate_fraud_rule(payload: DSLValidateRequest):
    dsl = payload.dsl_expression

    if len(dsl) < 3 or len(dsl) > 2000:
        return DSLValidationResponse(
            isValid=False,
            normalizedExpression=None,
            errors=[
                DSLError(
                    code="DSL_PARSE_ERROR",
                    message="Длина выражения должна быть от 3 до 2000 символов",
                    position=0,
                    near=dsl[:10] if dsl else "",
                )
            ],
        )

    return validate_rule(dsl)
