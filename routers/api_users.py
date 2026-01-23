import uuid

from authx import AuthX, AuthXConfig, RequestToken
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pwdlib import PasswordHash
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db import get_session
from models import User
from schemas import (
    AdminCreate,
    UserResponse,
    UserUpdate,
)

config = AuthXConfig(
    JWT_SECRET_KEY=settings.random_secret,
    JWT_ALGORITHM="HS256",
    JWT_TOKEN_LOCATION=["headers"],
    JWT_ACCESS_TOKEN_EXPIRES=3600,
)

auth = AuthX(config=config)
password_hash = PasswordHash.recommended()


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


router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get("/me", response_model=UserResponse)
async def get_me(
    token: RequestToken = Depends(auth.access_token_required),
    db: AsyncSession = Depends(get_session),
):
    user = await db.get(User, uuid.UUID(token.sub))
    if not user:
        raise HTTPException(status_code=404, detail="user is not found")
    return user


@router.put("/me", response_model=UserResponse)
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
        raise HTTPException(status_code=422, detail=str(e))

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


@router.get("/{id}", response_model=UserResponse)
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


@router.put("/{id}", response_model=UserResponse)
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


@router.get("")
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


@router.post("", response_model=UserResponse, status_code=201)
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


@router.delete("/{id}")
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
