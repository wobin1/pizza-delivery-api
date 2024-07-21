from pydantic import BaseModel
from typing import Optional, Any

class SignUpModel(BaseModel):
    id: Optional[int] = None
    username: str
    email: str
    password_hash: str
    is_staff: Optional[bool] = None
    is_active: Optional[bool] = None

    class Config:
        orm_mode=True
        schema_extra={
            'example': {
                "username": "johndoe",
                "email":"john@example.com",
                "password": "password",
                "is_staff": True,
                "is_active": True
            }
        }

class UserModel(BaseModel):
    id: Optional[Any]
    username: str
    email: str
    is_active: bool
    is_staff: bool

    class Config:
        from_attributes = True

class LoginModel(BaseModel):
    username: str
    password: str

class TokenModel(BaseModel):
    refresh_token: str

class ResponseModel(BaseModel):
    status: bool
    message: str
    data: Optional[Any] = None

class OrderModel(BaseModel):
    id: Optional[int] = None
    quantity:int
    order_status: Optional[str] = "PENDING"
    pizza_size: str
    user_id: Optional[int] 