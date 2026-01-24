import uuid

from authx import AuthX, AuthXConfig, RequestToken
from fastapi import Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from db import get_session
from models import User
from schemas import Role

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
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")
    if not user.is_active:
        raise HTTPException(status_code=423, detail="USER_INACTIVE")
    return user


async def is_admin(admin: User = Depends(get_current_user)):
    if not admin.role == Role.ADMIN:
        raise HTTPException(status_code=403, detail="FORBIDDEN")

    return admin
