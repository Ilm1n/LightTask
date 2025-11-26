from api.api_v1.demo_auth.demo_jwt_auth import UserDemoAuthSchema
from auth import utils_jwt as auth_utils


def create_jwt(token_data: dict) -> str:
    jwt_payload = {}
    jwt_payload.update(token_data)
    return auth_utils.encode_jwt(jwt_payload)


def create_access_token(
    user: UserDemoAuthSchema,
) -> str:
    jwt_payload = {
        "sub": user.username,
        "username": user.username,
        "email": user.email,
    }
    return auth_utils.encode_jwt(jwt_payload)


def create_refresh_token(
    user: UserDemoAuthSchema,
):
    return auth_utils.encode_jwt(jwt_payload)
