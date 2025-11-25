from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    username: str
    foo: int
    bar: int


class UserCreate(UserBase):
    pass


class UserRead(UserBase):
    id: int


class UserDemoAuthSchema(BaseModel):
    username: str
    password: bytes
    email: EmailStr | None = None
    is_active: bool = True
