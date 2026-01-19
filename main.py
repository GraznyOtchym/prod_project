import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime

from authx import AuthX, AuthXConfig, RequestToken
from authx.exceptions import JWTDecodeError
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pwdlib import PasswordHash
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db import Base, Session, async_engine, get_session
from models import FraudRule, User
from schemas import (
    AdminCreate,
    AuthResponse,
    FraudRuleCreate,
    FraudRuleResponse,
    FraudRuleUpdate,
    UserCreate,
    UserLogin,
    UserResponse,
    UserUpdate,
)

password_hash = PasswordHash.recommended()

config = AuthXConfig(
    JWT_SECRET_KEY=settings.random_secret,
    JWT_ALGORITHM="HS256",
    JWT_TOKEN_LOCATION=["headers"],
    JWT_ACCESS_TOKEN_EXPIRES=3600,
)

auth = AuthX(config=config)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with Session() as session:
        result = await session.execute(
            select(User).where(User.email == settings.admin_email)
        )
        admin_check = result.scalars().first()

        if not admin_check:
            new_admin = User(
                email=settings.admin_email,
                full_name=settings.admin_fullname,
                hashed_password=password_hash.hash(settings.admin_password),
                role="ADMIN",
                is_active=True,
                age=None,
                region=None,
                gender=None,
                marital_status=None,
            )
            session.add(new_admin)
            await session.commit()

    yield

    await async_engine.dispose()


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def test_middleware(request: Request, next_call):
    start = time.time()

    result = await next_call(request)

    result.headers["time"] = str(time.time() - start)

    return result


@app.exception_handler(JWTDecodeError)
async def authx_exception_handler(request, exc):
    return JSONResponse(
        status_code=401,
        content={"detail": "your token is invalid, try again"},
    )


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "code": "ERROR",
            "message": exc.detail,
            "traceId": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "path": request.url.path,
        },
    )


async def get_current_user(
    token: RequestToken = Depends(auth.token_required),
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


@app.get("/api/v1/ping")
async def ping():
    return {"status": "ok"}


@app.post("/api/v1/auth/register", response_model=AuthResponse, status_code=201)
async def registration(data: UserCreate, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.email == data.email))
    check_user = result.scalars().first()

    if check_user:
        raise HTTPException(status_code=409, detail="email is occupied")

    new_user = User(
        email=data.email,
        full_name=data.full_name,
        hashed_password=password_hash.hash(data.password),
        age=data.age,
        region=data.region,
        gender=data.gender,
        marital_status=data.marital_status,
        role="USER",
        is_active=True,
    )

    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)

    access_token = auth.create_access_token(
        uid=str(new_user.id), data={"role": new_user.role}
    )

    return {"accessToken": access_token, "expiresIn": 3600, "user": new_user}


@app.post("/api/v1/auth/login", response_model=AuthResponse)
async def login(data: UserLogin, session: AsyncSession = Depends(get_session)):
    user = await session.scalar(select(User).where(User.email == data.email))

    if not user or not password_hash.verify(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="data is incorrect")

    if not user.is_active:
        raise HTTPException(status_code=423, detail="user is deactivated")

    access_token = auth.create_access_token(uid=str(user.id), data={"role": user.role})

    return {"accessToken": access_token, "expiresIn": 3600, "user": user}


# ))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))


@app.get("/api/v1/users/me", response_model=UserResponse)
async def get_me(
    token: RequestToken = Depends(auth.access_token_required),
    db: AsyncSession = Depends(get_session),
):
    user = await db.get(User, uuid.UUID(token.sub))
    if not user:
        raise HTTPException(status_code=404, detail="user is not found")
    return user


@app.put("/api/v1/users/me", response_model=UserResponse)
async def update_me(
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json")

    if user.role != "ADMIN":
        if "role" in body or "isActive" in body:
            raise HTTPException(
                status_code=403, detail="Users cannot update role or isActive status"
            )
    try:
        data = UserUpdate(**body)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    user.full_name = data.full_name
    user.age = data.age
    user.region = data.region
    user.gender = data.gender
    user.marital_status = data.marital_status

    if user.role == "ADMIN":
        if "role" in body:
            user.role = body["role"]
        if "isActive" in body:
            user.is_active = body["isActive"]

    await session.commit()
    await session.refresh(user)
    return user


@app.get("/api/v1/users/{id}", response_model=UserResponse)
async def get_user(
    id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    if current_user.role != "ADMIN" and current_user.id != id:
        raise HTTPException(status_code=403, detail="forbidden")

    user = await session.get(User, id)
    if not user:
        raise HTTPException(status_code=404, detail="user is not found")

    return user


@app.put("/api/v1/users/{id}", response_model=UserResponse)
async def update_user(
    id: uuid.UUID,
    request: Request,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json")

    user_to_update = await session.get(User, id)
    if not user_to_update:
        raise HTTPException(status_code=404, detail="user is not found")

    if user.role != "ADMIN" and user.id != id:
        raise HTTPException(status_code=403, detail="forbidden")

    if user.role != "ADMIN":
        if "role" in body or "isActive" in body:
            raise HTTPException(status_code=403, detail="forbidden")

    try:
        data = UserUpdate(**body)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.errors())

    user_to_update.full_name = data.full_name
    user_to_update.age = data.age
    user_to_update.region = data.region
    user_to_update.gender = data.gender
    user_to_update.marital_status = data.marital_status

    if user.role == "ADMIN":
        if "role" in body:
            user_to_update.role = body["role"]
        if "isActive" in body:
            user_to_update.is_active = body["isActive"]

    await session.commit()
    await session.refresh(user_to_update)
    return user_to_update


@app.get("/api/v1/users")
async def user_list(
    page: int = Query(0),
    size: int = Query(20, ge=1, le=100),
    admin: User = Depends(is_admin),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(func.count(User.id))
    result = await session.execute(stmt)
    total = result.scalar()

    stmt = select(User).offset(page * size).limit(size)
    result = await session.execute(stmt)
    users = result.scalars().all()

    return {"items": users, "total": total, "page": page, "size": size}


@app.post("/api/v1/users", response_model=UserResponse, status_code=201)
async def create_user(
    data: AdminCreate,
    admin: User = Depends(is_admin),
    session: AsyncSession = Depends(get_session),
):
    check = await session.scalar(select(User).where(User.email == data.email))
    if check:
        raise HTTPException(status_code=409, detail="email is occupied")

    new_user = User(
        email=data.email,
        full_name=data.full_name,
        hashed_password=password_hash.hash(data.password),
        age=data.age,
        region=data.region,
        gender=data.gender,
        marital_status=data.marital_status,
        role=data.role.value,
        is_active=True,
    )
    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)
    return new_user


@app.delete("/api/v1/users/{id}")
async def deactivate_user(
    id: uuid.UUID,
    admin: User = Depends(is_admin),
    session: AsyncSession = Depends(get_session),
):
    user = await session.get(User, id)

    if not user:
        raise HTTPException(status_code=404, detail="user is not found")

    if user.is_active:
        user.is_active = False
        await session.commit()

    return JSONResponse(status_code=204, content=None)


@app.post("/api/v1/fraud-rules", status_code=201, response_model=FraudRuleResponse)
async def create_fraud_rule(
    data: FraudRuleCreate,
    admin: User = Depends(is_admin),
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


@app.get("/api/v1/fraud-rules")
async def get_fraud_rules(
    admin: User = Depends(is_admin), session: AsyncSession = Depends(get_session)
):
    result = await session.execute(select(FraudRule))
    rules = result.scalars().all()

    return rules


@app.get("/api/v1/fraud-rules/{id}", response_model=FraudRuleResponse)
async def get_fraud_rule_by_id(
    id: uuid.UUID,
    admin: User = Depends(is_admin),
    session: AsyncSession = Depends(get_session),
):
    rule = await session.get(FraudRule, id)

    if not rule:
        raise HTTPException(status_code=404, detail="rule is not found")

    return rule


@app.put("/api/v1/fraud-rules/{id}", response_model=FraudRuleResponse)
async def update_fraud_rule(
    id: uuid.UUID,
    request: Request,
    admin: User = Depends(is_admin),
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


@app.delete("/api/v1/fraud-rules/{id}", status_code=204)
async def deactivate_fraud_rule(
    id: uuid.UUID,
    admin: User = Depends(is_admin),
    session: AsyncSession = Depends(get_session),
):
    rule = await session.get(FraudRule, id)

    if not rule:
        raise HTTPException(status_code=404, detail="rule is not found")

    if rule.enabled:
        rule.enabled = False
        await session.commit()

    return JSONResponse(status_code=204, content=None)


@app.post("/api/v1/fraud-rules/validate")
async def validate_rule_stub(admin: User = Depends(is_admin)):
    raise HTTPException(status_code=422, detail="DSL_UNSUPPORTED_TIER")
