from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models
from passlib.context import CryptContext
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from datetime import datetime, timedelta
import jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
# FastAPI App
app = FastAPI()

models.Base.metadata.create_all(bind=engine)

# JWT Secret Key
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Rate Limiter (5 requests per minute)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)

# CORS Setup
origins = ["http://localhost", "http://localhost:3000", "http://localhost:5173", "https://puzzledsign.onrender.com"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.options("/{full_path:path}")
async def preflight_handler():
    return {"message": "Preflight request handled"}

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



# Schemas
class UserCreate(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class ScoreUpdate(BaseModel):
    time_taken: int

# Password Utilities
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed_password: str) -> bool:
    return pwd_context.verify(password, hashed_password)

# JWT Token Generation
def create_jwt_token(username: str):
    expiration = datetime.utcnow() + timedelta(days=10)  # Valid for 10 days
    payload = {"sub": username, "exp": expiration}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# JWT Token Verification
def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
def get_current_user_from_cookie(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        raise HTTPException(status_code=401, detail="Missing session token")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Register User
@app.post("/register/")
def register_user(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed_password = hash_password(user_data.password)
    new_user = models.User(username=user_data.username, password_hash=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    

    return {"message": "User registered successfully"}


# Login User (Rate Limited)
@app.post("/login/")
@limiter.limit("5/minute")  # Max 5 login attempts per minute
def login_user(request: Request, response: Response, user_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == user_data.username).first()
    if not user or not verify_password(user_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Generate JWT token
    token = create_jwt_token(user.username)

    # Prepare response
    resp = JSONResponse(
        content={
            "message": "Login successful",
            "username": user.username,
            "best_time": user.best_time,
        }
    )

    # Set cookies
    resp.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="Strict",
        max_age=60 * 60 * 24 * 10,
    )
    resp.set_cookie(
        key="session_user",
        value=user.username,
        httponly=True,
        secure=True,
        samesite="Strict",
        max_age=60 * 60 * 24 * 10,
    )

    return resp


# Update High Score
@app.post("/update-best-time/")
def update_best_time(request: Request, score_data: ScoreUpdate, db: Session = Depends(get_db)):
    username = get_current_user_from_cookie(request)

    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.best_time is None or score_data.time_taken < user.best_time:
        user.best_time = score_data.time_taken
        db.commit()
        return {"message": "Best time updated", "new_best_time": user.best_time}

    return {"message": "Time not a new record", "current_best_time": user.best_time}
# Get Leaderboard
@app.get("/leaderboard/")
def get_leaderboard(db: Session = Depends(get_db)):
    leaderboard = db.query(models.User).filter(models.User.best_time.isnot(None)).order_by(models.User.best_time.asc()).all()
    return [{"username": user.username, "best_time": user.best_time} for user in leaderboard]

@app.post("/logout/")
def logout_user(response: Response):
    response.delete_cookie(key="session_token")
    response.delete_cookie(key="session_user")
    return {"message": "Logged out successfully"}

@app.get("/ping")
def ping():
    return {"message": "pong"}