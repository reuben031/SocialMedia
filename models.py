#for login data input
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str
    role: str  # should be "admin" or "user"

class UserLogin(BaseModel):
    username: str
    password: str
