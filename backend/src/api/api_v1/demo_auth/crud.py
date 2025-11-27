from auth import utils_jwt as auth_utils
from core.schemas.user import UserDemoAuthSchema

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
