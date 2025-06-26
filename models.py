from pydantic import BaseModel
from enum import Enum

# ✅ Enum to restrict allowed roles
class Role(str, Enum):
    user = "user"
    admin = "admin"
    superadmin = "superadmin"

class UserCreate(BaseModel):
    username: str
    password: str
    role: Role  # restrict to user/admin/superadmin only

class UserLogin(BaseModel):
    username: str
    password: str
