import time
import uuid
from contextlib import asynccontextmanager

from authx import AuthX, AuthXConfig, RequestToken
from authx.exceptions import JWTDecodeError
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db import Base, Session, async_engine, get_session
from models import User
from schemas import AuthResponse, UserCreate, UserLogin, UserResponse

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

    access_token = auth.create_access_token(uid=str(new_user.id))

    return {"accessToken": access_token, "expiresIn": 3600, "user": new_user}


@app.post("/api/v1/auth/login", response_model=AuthResponse)
async def login(data: UserLogin, session: AsyncSession = Depends(get_session)):
    user = await session.scalar(select(User).where(User.email == data.email))

    if not user or not password_hash.verify(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="data is incorrect")

    if not user.is_active:
        raise HTTPException(status_code=423, detail="user is deactivated")

    access_token = auth.create_access_token(uid=str(user.id))

    return {"accessToken": access_token, "expiresIn": 3600, "user": user}


@app.get("/api/v1/users/me", response_model=UserResponse)
async def check_enter(
    token: RequestToken = Depends(auth.access_token_required),
    db: AsyncSession = Depends(get_session),
):
    user = await db.get(User, uuid.UUID(token.sub))
    if not user:
        raise HTTPException(status_code=404, detail="user is not found")
    return user
