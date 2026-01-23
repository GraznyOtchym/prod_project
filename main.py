import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from authx import AuthX, AuthXConfig, RequestToken
from authx.exceptions import JWTDecodeError, MissingTokenError
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db import Base, Session, async_engine, get_session
from models import User
from routers import api_users, fraud_rules, transactions
from schemas import AuthResponse, Role, UserCreate, UserLogin

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
        if not result.scalars().first():
            new_admin = User(
                email=settings.admin_email,
                full_name=settings.admin_fullname,
                hashed_password=password_hash.hash(settings.admin_password),
                role=Role.ADMIN,
                is_active=True,
            )
            session.add(new_admin)
            await session.commit()
    yield
    await async_engine.dispose()


app = FastAPI(
    title="Anti-fraud Service",
    lifespan=lifespan,
    swagger_ui_parameters={"persistAuthorization": True},
)

app.include_router(api_users.router)
app.include_router(fraud_rules.router)
app.include_router(transactions.router)


def error_response(status_code: int, code: str, message: str, path: str):
    return JSONResponse(
        status_code=status_code,
        content={
            "code": code,
            "message": message,
            "traceId": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "path": path,
        },
    )


@app.exception_handler(JWTDecodeError)
async def authx_exception_handler(request: Request, exc):
    return error_response(
        401, "INVALID_TOKEN", "Token is invalid or expired", request.url.path
    )


@app.exception_handler(MissingTokenError)
async def authx_token_error_handler(request: Request, exc):
    return error_response(
        401, "MISSING_TOKEN", "Bearer token is required", request.url.path
    )


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    error_code = "ERROR"
    if isinstance(exc.detail, str) and exc.detail.isupper():
        error_code = exc.detail

    return error_response(
        exc.status_code, error_code, str(exc.detail), request.url.path
    )


async def get_current_user(
    token: RequestToken = Depends(auth.access_token_required),
    session: AsyncSession = Depends(get_session),
):
    user = await session.get(User, uuid.UUID(token.sub))
    if not user:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")
    if not user.is_active:
        raise HTTPException(status_code=423, detail="USER_DEACTIVATED")
    return user


@app.get("/api/v1/ping")
async def ping():
    return {"status": "ok"}


@app.post("/api/v1/auth/register", response_model=AuthResponse, status_code=201)
async def registration(data: UserCreate, session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(User).where(User.email == data.email))
    if result.scalars().first():
        raise HTTPException(status_code=409, detail="EMAIL_ALREADY_EXISTS")

    new_user = User(
        email=data.email,
        full_name=data.full_name,
        hashed_password=password_hash.hash(data.password),
        age=data.age,
        region=data.region,
        gender=data.gender,
        marital_status=data.marital_status,
        role=Role.USER,
        is_active=True,
    )

    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)

    access_token = auth.create_access_token(uid=str(new_user.id), data={"role": "USER"})
    return {"accessToken": access_token, "expiresIn": 3600, "user": new_user}


@app.post("/api/v1/auth/login", response_model=AuthResponse)
async def login(data: UserLogin, session: AsyncSession = Depends(get_session)):
    user = await session.scalar(select(User).where(User.email == data.email))

    if not user or not password_hash.verify(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="INVALID_CREDENTIALS")

    if not user.is_active:
        raise HTTPException(status_code=423, detail="USER_DEACTIVATED")

    access_token = auth.create_access_token(uid=str(user.id), data={"role": user.role})
    return {"accessToken": access_token, "expiresIn": 3600, "user": user}
