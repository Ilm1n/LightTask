from fastapi import APIRouter

from core.config import settings

from .users import router as users_router

# demo_auth
from .demo_auth.demo_jwt_auth import router as demo_jwt_router

router = APIRouter(
    prefix=settings.api.v1.prefix,
)
router.include_router(
    users_router,
    prefix=settings.api.v1.users,
)

router.include_router(router=demo_jwt_router)
