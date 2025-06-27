from fastapi import FastAPI, HTTPException, Depends, status, Form
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from models import UserCreate, UserLogin
from utils import hash_password, verify_password
from database import fake_users_db
from auth import create_access_token, SECRET_KEY, ALGORITHM, get_current_user
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware  # ✅ NEW
import os

app = FastAPI()

# ✅ CORS CONFIG
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 👈 OR set to ["http://localhost:5500"] if you're using Live Server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

# 🔧 Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="JWT Auth API",
        version="1.0.0",
        description="Login with JWT and access protected routes",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "OAuth2PasswordBearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            if method in ["get", "post", "put", "delete"]:
                openapi_schema["paths"][path][method]["security"] = [{"OAuth2PasswordBearer": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# ✅ Signup
@app.post("/signup")
def signup(user: UserCreate):
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = hash_password(user.password)

    fake_users_db[user.username] = {
        "username": user.username,
        "password": hashed_pw,
        "role": user.role
    }

    print("\nCurrent fake_users_db:")
    print(fake_users_db)

    return {"message": f"User {user.username} created successfully"}

# ✅ Login (using HTML Form)
@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    db_user = fake_users_db.get(username)
    print("Current users:", fake_users_db)

    if not db_user or not verify_password(password, db_user["password"]):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    token = create_access_token({
        "sub": username,
        "role": db_user["role"]
    })

    return {
        "access_token": token,
        "token_type": "bearer"
    }

# ✅ Profile (any logged-in user)
@app.get("/profile")
def profile(current_user: dict = Depends(get_current_user)):
    return {
        "message": "Welcome to your profile!",
        "username": current_user["username"],
        "role": current_user["role"]
    }

# ✅ Admin-only route
@app.get("/admin-only")
def admin_only(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only!")
    return {
        "message": f"Hello Admin {current_user['username']}! You have access."
    }

@app.get("/")
def serve_home():
    return FileResponse(os.path.join("static", "index.html"))
