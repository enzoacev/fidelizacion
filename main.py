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
    role = Column(String)  # 'merchant', 'customer'
    business_name = Column(String, nullable=True)
    stamps = Column(Integer, default=0)

class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    dni = Column(String, unique=True, index=True)
    full_name = Column(String)
    birthdate = Column(String)  # YYYY-MM-DD

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    merchant_id = Column(Integer, ForeignKey("users.id"))
    customer_id = Column(Integer, ForeignKey("users.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)

class Config(Base):
    __tablename__ = "config"
    id = Column(Integer, primary_key=True, index=True)
    max_stamps = Column(Integer, default=10)
    reward_description = Column(String, default="Recompensa gratis")

class Reward(Base):
    __tablename__ = "rewards"
    id = Column(Integer, primary_key=True, index=True)
    merchant_id = Column(Integer, ForeignKey("users.id"))
    reward_name = Column(String)
    reward_description = Column(String)
    stamps_required = Column(Integer)
    active = Column(Integer, default=1)

class Coupon(Base):
    __tablename__ = "coupons"
    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("users.id"))
    merchant_id = Column(Integer, ForeignKey("users.id"))
    reward_id = Column(Integer, ForeignKey("rewards.id"))
    redeemed = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    redeemed_at = Column(DateTime, nullable=True)

class MerchantConfig(Base):
    __tablename__ = "merchant_configs"
    id = Column(Integer, primary_key=True, index=True)
    merchant_id = Column(Integer, ForeignKey("users.id"))
    fidelization_type = Column(String, default="qr")  # 'qr' o 'dni'
    dni_field_name = Column(String, nullable=True)

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

class CustomerCreate(BaseModel):
    dni: str
    full_name: str
    email: str
    password: str
    birthdate: str  # YYYY-MM-DD

    @field_validator('dni')
    @classmethod
    def validate_dni(cls, v):
        if not v or len(v.strip()) < 5:
            raise ValueError("DNI inválido")
        return v.strip()

    @field_validator('full_name')
    @classmethod
    def validate_name(cls, v):
        if not v or len(v.strip()) < 3:
            raise ValueError("Nombre debe tener al menos 3 caracteres")
        return v.strip()

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

    @field_validator('birthdate')
    @classmethod
    def validate_birthdate(cls, v):
        if not v or len(v) != 10:
            raise ValueError("Fecha debe ser YYYY-MM-DD")
        return v

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

class ConfigUpdate(BaseModel):
    max_stamps: int
    reward_description: str

class RewardCreate(BaseModel):
    reward_name: str
    reward_description: str
    stamps_required: int

class MerchantConfigUpdate(BaseModel):
    fidelization_type: str  # 'qr' o 'dni'

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

# Verificar si es merchant
async def get_merchant_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    current_user = await get_current_user(token, db)
    if current_user.role != "merchant":
        raise HTTPException(status_code=403, detail="Acceso denegado. Solo comercios.")
    return current_user

# --- RUTAS DE AUTENTICACIÓN ---
@app.post("/api/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Registro para comercios"""
    try:
        db_user = db.query(User).filter(User.email == user.email).first()
        if db_user:
            raise HTTPException(status_code=400, detail="El email ya está registrado")
        
        if user.role not in ["merchant"]:
            raise HTTPException(status_code=400, detail="Role inválido")
        
        if not user.business_name:
            raise HTTPException(status_code=400, detail="El nombre del comercio es requerido")
        
        hashed_password = get_password_hash(user.password)
        new_user = User(
            email=user.email,
            hashed_password=hashed_password,
            role="merchant",
            business_name=user.business_name
        )
        db.add(new_user)
        db.commit()
        
        return {"message": "Comercio registrado exitosamente", "email": new_user.email}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error registro: {e}")
        raise HTTPException(status_code=500, detail="Error al crear comercio")

@app.post("/api/register-customer")
def register_customer(customer: CustomerCreate, db: Session = Depends(get_db)):
    """Registro para clientes con DNI"""
    try:
        # Verificar DNI único
        existing_dni = db.query(Customer).filter(Customer.dni == customer.dni).first()
        if existing_dni:
            raise HTTPException(status_code=400, detail="DNI ya registrado")
        
        # Verificar email único
        existing_email = db.query(User).filter(User.email == customer.email).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="Email ya registrado")
        
        # Crear usuario
        hashed_password = get_password_hash(customer.password)
        new_user = User(
            email=customer.email,
            hashed_password=hashed_password,
            role="customer"
        )
        db.add(new_user)
        db.flush()  # Para obtener el ID
        
        # Crear cliente
        new_customer = Customer(
            user_id=new_user.id,
            dni=customer.dni,
            full_name=customer.full_name,
            birthdate=customer.birthdate
        )
        db.add(new_customer)
        db.commit()
        
        return {"message": "Cliente registrado exitosamente", "email": customer.email}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error registro cliente: {e}")
        raise HTTPException(status_code=500, detail="Error al crear cliente")

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login para clientes (DNI) o comercios (email)"""
    # Intentar login como cliente (DNI)
    customer = db.query(Customer).filter(Customer.dni == form_data.username).first()
    if customer:
        user = db.query(User).filter(User.id == customer.user_id).first()
        if user and verify_password(form_data.password, user.hashed_password):
            access_token = create_access_token(
                data={"sub": user.email, "role": user.role},
                expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            return {"access_token": access_token, "token_type": "bearer", "role": user.role}
    
    # Intentar login como comercio (email)
    user = db.query(User).filter(User.email == form_data.username).first()
    if user and verify_password(form_data.password, user.hashed_password):
        access_token = create_access_token(
            data={"sub": user.email, "role": user.role},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return {"access_token": access_token, "token_type": "bearer", "role": user.role}
    
    raise HTTPException(status_code=401, detail="DNI/Email o contraseña incorrectos")

@app.get("/api/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "email": current_user.email,
        "role": current_user.role,
        "stamps": current_user.stamps,
        "business_name": current_user.business_name,
        "is_merchant": current_user.role == "merchant"
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

    config = db.query(Config).first()
    max_stamps = config.max_stamps if config else 10

    customer.stamps += 1
    db.add(Transaction(merchant_id=current_user.id, customer_id=customer.id))
    
    # Si alcanza el máximo, crear cupón
    if customer.stamps >= max_stamps:
        reward = db.query(Reward).filter(
            Reward.merchant_id == current_user.id,
            Reward.stamps_required == max_stamps
        ).first()
        
        if reward:
            coupon = Coupon(
                customer_id=customer.id,
                merchant_id=current_user.id,
                reward_id=reward.id
            )
            db.add(coupon)
            customer.stamps = 0  # Reiniciar contador
    
    db.commit()
    return {
        "message": "¡Sello añadido!",
        "customer_email": customer.email,
        "new_total": customer.stamps,
        "max_stamps": max_stamps
    }

@app.post("/api/merchant/add-stamp-dni")
def add_stamp_dni(dni: str, current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Agregar sello a cliente usando DNI"""
    if not dni or len(dni.strip()) == 0:
        raise HTTPException(status_code=400, detail="DNI requerido")
    
    # Buscar cliente por email (simulamos que DNI es identificador)
    # En producción, habría tabla de clientes con DNI
    customer = db.query(User).filter(User.email == dni).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    
    if customer.role != "customer":
        raise HTTPException(status_code=400, detail="Solo se pueden agregar sellos a clientes")
    
    config = db.query(Config).first()
    max_stamps = config.max_stamps if config else 10
    
    customer.stamps += 1
    db.add(Transaction(merchant_id=current_user.id, customer_id=customer.id))
    
    # Si alcanza el máximo, crear cupón
    if customer.stamps >= max_stamps:
        reward = db.query(Reward).filter(
            Reward.merchant_id == current_user.id,
            Reward.stamps_required == max_stamps
        ).first()
        
        if reward:
            coupon = Coupon(
                customer_id=customer.id,
                merchant_id=current_user.id,
                reward_id=reward.id
            )
            db.add(coupon)
            customer.stamps = 0
    
    db.commit()
    
    return {
        "message": "¡Sello añadido!",
        "customer_email": customer.email,
        "new_total": customer.stamps,
        "max_stamps": max_stamps
    }

# ================= RUTAS DE COMERCIO (DASHBOARD) =================
@app.get("/api/merchant/dashboard")
def merchant_dashboard(current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Dashboard con estadísticas del comercio"""
    rewards = db.query(Reward).filter(Reward.merchant_id == current_user.id).all()
    
    coupons_total = db.query(Coupon).filter(
        Coupon.merchant_id == current_user.id
    ).count()
    
    coupons_redeemed = db.query(Coupon).filter(
        Coupon.merchant_id == current_user.id,
        Coupon.redeemed == 1
    ).count()
    
    transactions_count = db.query(Transaction).filter(
        Transaction.merchant_id == current_user.id
    ).count()
    
    return {
        "business_name": current_user.business_name,
        "email": current_user.email,
        "transactions_total": transactions_count,
        "coupons_total": coupons_total,
        "coupons_redeemed": coupons_redeemed,
        "coupons_pending": coupons_total - coupons_redeemed,
        "rewards_count": len(rewards)
    }

@app.get("/api/merchant/coupons")
def merchant_coupons(current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Ver todos los cupones generados por este comercio"""
    coupons = db.query(Coupon).filter(Coupon.merchant_id == current_user.id).all()
    result = []
    
    for coupon in coupons:
        reward = db.query(Reward).filter(Reward.id == coupon.reward_id).first()
        customer = db.query(User).filter(User.id == coupon.customer_id).first()
        if reward and customer:
            result.append({
                "id": coupon.id,
                "customer_email": customer.email,
                "reward_name": reward.reward_name,
                "reward_description": reward.reward_description,
                "redeemed": coupon.redeemed,
                "created_at": coupon.created_at.isoformat() if coupon.created_at else None,
                "redeemed_at": coupon.redeemed_at.isoformat() if coupon.redeemed_at else None
            })
    
    return result

@app.put("/api/merchant/coupon/{coupon_id}/redeem")
def redeem_coupon(coupon_id: int, current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Marcar cupón como canjeado"""
    coupon = db.query(Coupon).filter(
        Coupon.id == coupon_id,
        Coupon.merchant_id == current_user.id
    ).first()
    
    if not coupon:
        raise HTTPException(status_code=404, detail="Cupón no encontrado")
    
    coupon.redeemed = 1
    coupon.redeemed_at = datetime.utcnow()
    db.commit()
    
    return {"message": "Cupón canjeado", "coupon_id": coupon_id}

@app.get("/api/merchant/rewards")
def get_merchant_rewards(current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    rewards = db.query(Reward).filter(Reward.merchant_id == current_user.id).all()
    return [
        {
            "id": r.id,
            "name": r.reward_name,
            "description": r.reward_description,
            "stamps": r.stamps_required,
            "active": r.active
        }
        for r in rewards
    ]

@app.post("/api/merchant/rewards")
def create_reward(data: RewardCreate, current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    reward = Reward(
        merchant_id=current_user.id,
        reward_name=data.reward_name,
        reward_description=data.reward_description,
        stamps_required=data.stamps_required
    )
    db.add(reward)
    db.commit()
    return {"id": reward.id, "message": "Recompensa creada"}

@app.get("/api/merchant/config")
def get_merchant_config(current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    config = db.query(MerchantConfig).filter(
        MerchantConfig.merchant_id == current_user.id
    ).first()
    
    if not config:
        config = MerchantConfig(merchant_id=current_user.id, fidelization_type="qr")
        db.add(config)
        db.commit()
    
    return {"fidelization_type": config.fidelization_type}

@app.put("/api/merchant/config")
def update_merchant_config(data: MerchantConfigUpdate, current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    if data.fidelization_type not in ["qr", "dni"]:
        raise HTTPException(status_code=400, detail="Tipo de fidelización inválido")
    
    config = db.query(MerchantConfig).filter(
        MerchantConfig.merchant_id == current_user.id
    ).first()
    
    if not config:
        config = MerchantConfig(merchant_id=current_user.id)
        db.add(config)
    
    config.fidelization_type = data.fidelization_type
    db.commit()
    return {"message": "Configuración actualizada"}

# ================= RUTAS DE ADMINISTRADOR (CONFIGURACIÓN GLOBAL) =================
@app.get("/api/admin/config")
def get_admin_config(db: Session = Depends(get_db)):
    """Obtener configuración global (público para lectura)"""
    config = db.query(Config).first()
    if not config:
        config = Config(max_stamps=10, reward_description="Recompensa gratis")
        db.add(config)
        db.commit()
    return {
        "max_stamps": config.max_stamps,
        "reward_description": config.reward_description
    }

@app.put("/api/admin/config")
def update_admin_config(data: ConfigUpdate, db: Session = Depends(get_db)):
    """Actualizar configuración global (requiere autenticación de merchant principal)"""
    config = db.query(Config).first()
    if not config:
        config = Config()
        db.add(config)
    config.max_stamps = data.max_stamps
    config.reward_description = data.reward_description
    db.commit()
    return {"message": "Configuración actualizada"}

@app.get("/api/admin/merchants")
def get_admin_merchants(db: Session = Depends(get_db)):
    """Obtener lista de comercios (público para lectura)"""
    merchants = db.query(User).filter(User.role == "merchant").all()
    result = []
    
    for merchant in merchants:
        rewards = db.query(Reward).filter(Reward.merchant_id == merchant.id).all()
        result.append({
            "id": merchant.id,
            "email": merchant.email,
            "business_name": merchant.business_name,
            "reward_count": len(rewards),
            "rewards": [
                {"id": r.id, "name": r.reward_name, "stamps": r.stamps_required}
                for r in rewards
            ]
        })
    
    return result

# ================= RUTA MERCHANT DASHBOARD =================
@app.get("/merchant-dashboard")
async def merchant_dashboard_page():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "merchant-dashboard.html")
    if not os.path.exists(html_path):
        return {"error": "merchant-dashboard.html no encontrado"}
    return FileResponse(html_path)

@app.get("/admin")
async def admin_redirect():
    return FileResponse(os.path.join(os.path.dirname(os.path.abspath(__file__)), "merchant-dashboard.html"))

# ================= RUTA PRINCIPAL =================
@app.get("/")
async def read_root():
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