from fastapi import APIRouter, Depends

from core.schemas.user import UserDemoAuthSchema

from auth import utils_jwt as auth_utils

router = APIRouter(prefix="/jwt", tags=["JWT"])

john = UserDemoAuthSchema(
    username="john",
    password=auth_utils.hash_password("qwerty"),
    email="john@example.com",
)

sam = UserDemoAuthSchema(
    username="sam",
    password=auth_utils.hash_password("secret"),
)

users_db: dict[str, UserDemoAuthSchema] = {
    john.username: john,
    sam.username: sam,
}


router.post("/login/")


def validate_auth_user():
    pass


def auth_user_issue_jwt(
    user: UserDemoAuthSchema = Depends(validate_auth_user),
):
    token = auth_utils.encode_jwt(user)
    return token
