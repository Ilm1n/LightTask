from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    username: str
    foo: int
    bar: int


class UserCreate(UserBase):
    pass


class UserRead(UserBase):
    id: int

