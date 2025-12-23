import uvicorn
import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from pydantic import BaseModel, field_validator
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext

# ================= CONFIGURACIÓN CLOUD READY =================
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
QR_TOKEN_EXPIRE_SECONDS = 60

# Base de Datos Dinámica
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./loyalty.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# ================= BASE DE DATOS =================
if DATABASE_URL.startswith("postgresql"):
    engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=3600)
else:
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)
    business_name = Column(String, nullable=True)
    stamps = Column(Integer, default=0)

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    merchant_id = Column(Integer, ForeignKey("users.id"))
    customer_id = Column(Integer, ForeignKey("users.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ================= SEGURIDAD =================
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class UserCreate(BaseModel):
    email: str
    password: str
    role: str
    business_name: Optional[str] = None

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not v or "@" not in v:
            raise ValueError("Email inválido")
        return v.lower().strip()

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not v or len(v) < 6:
            raise ValueError("La contraseña debe tener al menos 6 caracteres")
        return v

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

# ================= APP FASTAPI =================
app = FastAPI(title="Loyalty MVP")

# CORS Middleware (crítico para frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# --- RUTAS ---
@app.post("/api/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    try:
        db_user = db.query(User).filter(User.email == user.email).first()
        if db_user:
            raise HTTPException(status_code=400, detail="El email ya está registrado")
        
        if user.role not in ["customer", "merchant"]:
            raise HTTPException(status_code=400, detail="Role inválido")
        
        if user.role == "merchant" and not user.business_name:
            raise HTTPException(status_code=400, detail="El nombre del comercio es requerido")
        
        hashed_password = get_password_hash(user.password)
        new_user = User(
            email=user.email,
            hashed_password=hashed_password,
            role=user.role,
            business_name=user.business_name if user.role == "merchant" else None
        )
        db.add(new_user)
        db.commit()
        
        return {"message": "Usuario creado exitosamente", "email": new_user.email}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error registro: {e}")
        raise HTTPException(status_code=500, detail="Error al crear usuario")

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Email o contraseña incorrectos")
    
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

@app.get("/api/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "email": current_user.email,
        "role": current_user.role,
        "stamps": current_user.stamps,
        "business_name": current_user.business_name
    }

@app.get("/api/customer/qr-token")
def get_qr_token(current_user: User = Depends(get_current_user)):
    if current_user.role != "customer":
        raise HTTPException(status_code=403, detail="Acceso denegado")
    
    qr_data = {"user_id": current_user.id, "type": "qr_stamp"}
    token = create_access_token(
        data=qr_data,
        expires_delta=timedelta(seconds=QR_TOKEN_EXPIRE_SECONDS)
    )
    return {"qr_token": token, "expires_in": QR_TOKEN_EXPIRE_SECONDS}

@app.post("/api/merchant/scan")
def scan_qr(qr_token: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "merchant":
        raise HTTPException(status_code=403, detail="Acceso denegado")

    try:
        payload = jwt.decode(qr_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "qr_stamp":
            raise HTTPException(status_code=400, detail="QR inválido")
    except JWTError:
        raise HTTPException(status_code=400, detail="QR expirado o inválido")

    customer = db.query(User).filter(User.id == payload.get("user_id")).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    customer.stamps += 1
    db.add(Transaction(merchant_id=current_user.id, customer_id=customer.id))
    db.commit()

    return {
        "message": "¡Sello añadido!",
        "customer_email": customer.email,
        "new_total": customer.stamps
    }

# ================= RUTA PRINCIPAL =================
@app.get("/")
async def read_root():
    # Usar ruta absoluta para compatibilidad con Render
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
    if not os.path.exists(html_path):
        return {"error": "index.html no encontrado"}
    return FileResponse(html_path)

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)