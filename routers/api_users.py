import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pwdlib import PasswordHash
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db import get_session
from dependencies import get_current_user, is_admin
from models import User
from schemas import AdminCreate, Role, UserList, UserResponse, UserUpdate

password_hash = PasswordHash.recommended()
router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
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
        raise HTTPException(status_code=400, detail="BAD_REQUEST")

    if user.role != Role.ADMIN:
        if "role" in body or "isActive" in body:
            raise HTTPException(status_code=403, detail="FORBIDDEN")

    try:
        data = UserUpdate(**body)
    except ValidationError:
        raise HTTPException(status_code=422, detail="VALIDATION_FAILED")

    user.full_name = data.full_name
    user.age = data.age
    user.region = data.region
    user.gender = data.gender
    user.marital_status = data.marital_status

    if user.role == Role.ADMIN:
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
    if current_user.role != Role.ADMIN and current_user.id != id:
        raise HTTPException(status_code=403, detail="FORBIDDEN")

    user = await session.get(User, id)
    if not user:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    return user


@router.put("/{id}", response_model=UserResponse)
async def update_user(
    id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    user_to_update = await session.get(User, id)
    if not user_to_update:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    if current_user.role != Role.ADMIN and current_user.id != id:
        raise HTTPException(status_code=403, detail="FORBIDDEN")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="BAD_REQUEST")

    if current_user.role != Role.ADMIN and ("role" in body or "isActive" in body):
        raise HTTPException(status_code=403, detail="FORBIDDEN")

    data = UserUpdate(**body)

    for field, value in data.model_dump(exclude_unset=True).items():
        setattr(user_to_update, field, value)

    if current_user.role == Role.ADMIN:
        if "role" in body:
            user_to_update.role = body["role"]
        if "isActive" in body:
            user_to_update.is_active = body["isActive"]

    await session.commit()
    await session.refresh(user_to_update)
    return user_to_update


@router.get("", response_model=UserList)
async def user_list(
    page: int = Query(0, ge=0),
    size: int = Query(20, ge=1, le=100),
    admin: User = Depends(is_admin),
    session: AsyncSession = Depends(get_session),
):
    total = await session.scalar(select(func.count(User.id)))

    result = await session.execute(
        select(User).order_by(User.created_at).offset(page * size).limit(size)
    )
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
        raise HTTPException(status_code=409, detail="EMAIL_ALREADY_EXISTS")

    new_user = User(
        email=data.email,
        full_name=data.full_name,
        hashed_password=password_hash.hash(data.password),
        age=data.age,
        region=data.region,
        gender=data.gender,
        marital_status=data.marital_status,
        role=data.role,
        is_active=True,
    )
    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)
    return new_user


@router.delete("/{id}", status_code=204)
async def deactivate_user(
    id: uuid.UUID,
    admin: User = Depends(is_admin),
    session: AsyncSession = Depends(get_session),
):
    user = await session.get(User, id)
    if not user:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    if user.is_active:
        user.is_active = False
        await session.commit()

    return None
