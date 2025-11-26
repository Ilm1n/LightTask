from jwt.exceptions import InvalidTokenError
from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    status,
)
from fastapi.security import (
    OAuth2PasswordBearer,
)
from pydantic import BaseModel, EmailStr

from api.api_v1.demo_auth.helpers import create_access_token, create_refresh_token
from auth import utils_jwt as auth_utils

# http_bearer = HTTPBearer()
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/jwt/login/",
)

router = APIRouter(prefix="/jwt", tags=["JWT"])


class UserDemoAuthSchema(BaseModel):
    username: str
    password: bytes
    email: EmailStr | None = None
    is_active: bool = True


class TokenInfo(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"


john = UserDemoAuthSchema(
    username="john",
    password=auth_utils.hash_password("qwerty"),
    email="john@example.com",
)

sam = UserDemoAuthSchema(
    username="sam",
    password=auth_utils.hash_password("secret"),
)

dima = UserDemoAuthSchema(
    username="dima",
    password=auth_utils.hash_password("asd"),
    email="dima@example.com",
    is_active=False,
)

users_db: dict[str, UserDemoAuthSchema] = {
    john.username: john,
    sam.username: sam,
    dima.username: dima,
}


def validate_auth_user(
    username: str = Form(),
    password: str = Form(),
):
    unauthed_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid username or password",
    )
    if not (user := users_db.get(username)):
        raise unauthed_exc

    if not auth_utils.validate_password(
        password=password,
        hashed_password=user.password,
    ):
        raise unauthed_exc

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="inactive user",
        )
    return user


def get_current_token_payload(
    # credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
    token: str = Depends(oauth2_scheme),
) -> UserDemoAuthSchema:
    # token = credentials.credentials
    try:
        payload = auth_utils.decode_jwt(
            token=token,
        )
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token error",
        )
    return payload


def get_current_auth_user(
    payload: dict = Depends(get_current_token_payload),
) -> UserDemoAuthSchema:
    username: str = payload.get("sub")
    if user := users_db.get(username):
        return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="token invalid",
    )


def get_current_active_auth_user(
    user: UserDemoAuthSchema = Depends(get_current_auth_user),
):
    if user.is_active:
        return user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="inactive user",
    )


@router.post("/login/")
def auth_user_issue_jwt(
    user: UserDemoAuthSchema = Depends(validate_auth_user),
):
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)
    return TokenInfo(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.get("/users/me/")
def auth_user_check_self_info(
    payload: dict = Depends(get_current_token_payload),
    user: UserDemoAuthSchema = Depends(get_current_active_auth_user),
):
    iat = payload.get("iat")
    return {
        "username": user.username,
        "email": user.email,
        "logged_in": iat,
    }
