from pydantic import BaseModel
from typing import Optional

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



class LoginModel(BaseModel):
    username: str
    password: str

class TokenModel(BaseModel):
    refresh_token: str