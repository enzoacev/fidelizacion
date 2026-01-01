import uvicorn
import os
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean
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
    role = Column(String)  # 'merchant', 'customer', 'admin'
    business_name = Column(String, nullable=True)
    stamps = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)

class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True)
    dni = Column(String, unique=True, index=True)
    full_name = Column(String)
    birthdate = Column(String)  # YYYY-MM-DD
    pin = Column(String)  # Hashed 4-digit PIN

class Branch(Base):
    __tablename__ = "branches"
    id = Column(Integer, primary_key=True, index=True)
    merchant_id = Column(Integer, ForeignKey("users.id"))
    branch_name = Column(String)
    location = Column(String, nullable=True)
    stamps_valid_all_branches = Column(Boolean, default=False)  # Si True, sellos válidos en todas
    created_at = Column(DateTime, default=datetime.utcnow)

class CustomerMerchant(Base):
    __tablename__ = "customer_merchant"
    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("users.id"))
    merchant_id = Column(Integer, ForeignKey("users.id"))
    branch_id = Column(Integer, ForeignKey("branches.id"), nullable=True)
    stamps = Column(Integer, default=0)
    max_stamps = Column(Integer, default=10)  # ← NUEVO: guardar max_stamps por tarjeta
    created_at = Column(DateTime, default=datetime.utcnow)

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True, index=True)
    merchant_id = Column(Integer, ForeignKey("users.id"))
    branch_id = Column(Integer, ForeignKey("branches.id"), nullable=True)
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
    branch_id = Column(Integer, ForeignKey("branches.id"), nullable=True)
    reward_name = Column(String)
    reward_description = Column(String)
    stamps_required = Column(Integer)
    active = Column(Integer, default=1)

class Coupon(Base):
    __tablename__ = "coupons"
    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("users.id"))
    merchant_id = Column(Integer, ForeignKey("users.id"))
    branch_id = Column(Integer, ForeignKey("branches.id"), nullable=True)
    reward_id = Column(Integer, ForeignKey("rewards.id"))
    redeemed = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    redeemed_at = Column(DateTime, nullable=True)

class MerchantConfig(Base):
    __tablename__ = "merchant_configs"
    id = Column(Integer, primary_key=True, index=True)
    merchant_id = Column(Integer, ForeignKey("users.id"))
    fidelization_type = Column(String, default="qr")  # 'qr' o 'dni'
    max_stamps = Column(Integer, default=10)  # ← AGREGAR ESTA COLUMNA

Base.metadata.create_all(bind=engine)

# ================= MIGRACIÓN AUTOMÁTICA =================
def migrate_database():
    """Agrega columnas faltantes a la BD existente"""
    from sqlalchemy import inspect, text
    
    inspector = inspect(engine)
    
    # Verificar si customers.pin existe
    if "customers" in inspector.get_table_names():
        columns = [col["name"] for col in inspector.get_columns("customers")]
        if "pin" not in columns:
            with engine.begin() as conn:
                if engine.dialect.name == "sqlite":
                    conn.execute(text("ALTER TABLE customers ADD COLUMN pin TEXT"))
                    print("✓ Columna 'pin' agregada a 'customers'")
                elif engine.dialect.name == "postgresql":
                    conn.execute(text("ALTER TABLE customers ADD COLUMN pin TEXT"))
                    print("✓ Columna 'pin' agregada a 'customers'")
    
    # Verificar si customer_merchant.max_stamps existe
    if "customer_merchant" in inspector.get_table_names():
        columns = [col["name"] for col in inspector.get_columns("customer_merchant")]
        if "max_stamps" not in columns:
            with engine.begin() as conn:
                if engine.dialect.name == "sqlite":
                    conn.execute(text("ALTER TABLE customer_merchant ADD COLUMN max_stamps INTEGER DEFAULT 10"))
                    print("✓ Columna 'max_stamps' agregada a 'customer_merchant'")
                elif engine.dialect.name == "postgresql":
                    conn.execute(text("ALTER TABLE customer_merchant ADD COLUMN max_stamps INTEGER DEFAULT 10"))
                    print("✓ Columna 'max_stamps' agregada a 'customer_merchant'")
    
    # Verificar si merchant_configs.max_stamps existe
    if "merchant_configs" in inspector.get_table_names():
        columns = [col["name"] for col in inspector.get_columns("merchant_configs")]
        if "max_stamps" not in columns:
            with engine.begin() as conn:
                if engine.dialect.name == "sqlite":
                    conn.execute(text("ALTER TABLE merchant_configs ADD COLUMN max_stamps INTEGER DEFAULT 10"))
                    print("✓ Columna 'max_stamps' agregada a 'merchant_configs'")
                elif engine.dialect.name == "postgresql":
                    conn.execute(text("ALTER TABLE merchant_configs ADD COLUMN max_stamps INTEGER DEFAULT 10"))
                    print("✓ Columna 'max_stamps' agregada a 'merchant_configs'")

migrate_database()

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

# ================= PYDANTIC MODELS =================
class MerchantCreate(BaseModel):
    email: str
    password: str
    business_name: str

class CustomerCreate(BaseModel):
    dni: str
    full_name: str
    email: str
    pin: str  # 4 dígitos
    birthdate: str

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

    @field_validator('pin')
    @classmethod
    def validate_pin(cls, v):
        if not v or not v.isdigit() or len(v) != 4:
            raise ValueError("PIN debe ser 4 dígitos")
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

class BranchCreate(BaseModel):
    branch_name: str
    location: Optional[str] = None
    stamps_valid_all_branches: bool = False

class RewardCreate(BaseModel):
    reward_name: str
    reward_description: str
    stamps_required: int

class MerchantConfigUpdate(BaseModel):
    fidelization_type: str

class PinUpdate(BaseModel):
    old_pin: str
    new_pin: str

# Agregar modelo Pydantic para actualizar max_stamps
class MerchantMaxStampsUpdate(BaseModel):
    max_stamps: int

    @field_validator('max_stamps')
    @classmethod
    def validate_max_stamps(cls, v):
        if v < 1 or v > 100:
            raise ValueError("max_stamps debe estar entre 1 y 100")
        return v

# ================= APP FASTAPI =================
app = FastAPI(title="Loyalty MVP")

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

async def get_merchant_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    current_user = await get_current_user(token, db)
    if current_user.role not in ["merchant", "admin"]:
        raise HTTPException(status_code=403, detail="Acceso denegado")
    return current_user

async def get_admin_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    current_user = await get_current_user(token, db)
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Acceso solo para administradores")
    return current_user

# ================= RUTAS DE AUTENTICACIÓN =================
@app.post("/api/register-merchant")
def register_merchant(user: MerchantCreate, db: Session = Depends(get_db)):
    """Registro para comercios"""
    try:
        db_user = db.query(User).filter(User.email == user.email).first()
        if db_user:
            raise HTTPException(status_code=400, detail="El email ya está registrado")
        
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
        print(f"Error registro merchant: {e}")
        raise HTTPException(status_code=500, detail="Error al crear comercio")

@app.post("/api/register-customer")
def register_customer(customer: CustomerCreate, db: Session = Depends(get_db)):
    """Registro para clientes con DNI y PIN"""
    try:
        existing_dni = db.query(Customer).filter(Customer.dni == customer.dni).first()
        if existing_dni:
            raise HTTPException(status_code=400, detail="DNI ya registrado")
        
        existing_email = db.query(User).filter(User.email == customer.email).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="Email ya registrado")
        
        hashed_pin = get_password_hash(customer.pin)
        new_user = User(
            email=customer.email,
            hashed_password=hashed_pin,  # PIN hasheado
            role="customer"
        )
        db.add(new_user)
        db.flush()
        
        new_customer = Customer(
            user_id=new_user.id,
            dni=customer.dni,
            full_name=customer.full_name,
            birthdate=customer.birthdate,
            pin=hashed_pin
        )
        db.add(new_customer)
        db.commit()
        
        return {"message": "Cliente registrado exitosamente", "email": customer.email}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"Error registro customer: {e}")
        raise HTTPException(status_code=500, detail="Error al crear cliente")

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login separado para cliente (DNI+PIN) o comercio (email+password)"""
    # Intentar login como cliente (DNI + PIN)
    customer = db.query(Customer).filter(Customer.dni == form_data.username).first()
    if customer:
        if verify_password(form_data.password, customer.pin):
            user = db.query(User).filter(User.id == customer.user_id).first()
            if user:
                access_token = create_access_token(
                    data={"sub": user.email, "role": user.role},
                    expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
                )
                return {"access_token": access_token, "token_type": "bearer", "role": user.role}
    
    # Intentar login como comercio (email + password)
    user = db.query(User).filter(User.email == form_data.username).first()
    if user and user.role in ["merchant", "admin"] and verify_password(form_data.password, user.hashed_password):
        access_token = create_access_token(
            data={"sub": user.email, "role": user.role},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return {"access_token": access_token, "token_type": "bearer", "role": user.role}
    
    raise HTTPException(status_code=401, detail="Credenciales inválidas")

@app.get("/api/me")
def read_users_me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    customer_data = None
    if current_user.role == "customer":
        customer = db.query(Customer).filter(Customer.user_id == current_user.id).first()
        if customer:
            customer_data = {
                "dni": customer.dni,
                "full_name": customer.full_name,
                "birthdate": customer.birthdate
            }
    
    return {
        "email": current_user.email,
        "role": current_user.role,
        "business_name": current_user.business_name,
        "customer": customer_data
    }

# ================= RUTAS CLIENTE =================
@app.get("/api/customer/cards")
def get_customer_cards(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Ver todas las tarjetas de fidelización del cliente"""
    if current_user.role != "customer":
        raise HTTPException(status_code=403, detail="Solo clientes pueden ver tarjetas")
    
    cards = db.query(CustomerMerchant).filter(
        CustomerMerchant.customer_id == current_user.id
    ).all()
    
    result = []
    
    for card in cards:
        merchant = db.query(User).filter(User.id == card.merchant_id).first()
        if merchant:
            result.append({
                "id": card.id,
                "merchant_name": merchant.business_name,
                "merchant_email": merchant.email,
                "stamps": card.stamps,
                "max_stamps": card.max_stamps,  # ← USAR max_stamps de la tarjeta
                "branch_id": card.branch_id
            })
    
    return result

@app.get("/api/customer/qr-token")
def get_qr_token(current_user: User = Depends(get_current_user), merchant_id: int = None, db: Session = Depends(get_db)):
    """Generar QR para un comercio específico"""
    if current_user.role != "customer":
        raise HTTPException(status_code=403, detail="Solo clientes pueden generar QR")
    
    # Verificar que el cliente tiene tarjeta con ese comercio
    if merchant_id:
        card = db.query(CustomerMerchant).filter(
            CustomerMerchant.customer_id == current_user.id,
            CustomerMerchant.merchant_id == merchant_id
        ).first()
        if not card:
            raise HTTPException(status_code=404, detail="No tienes tarjeta en este comercio")
    
    qr_data = {"user_id": current_user.id, "type": "qr_stamp", "merchant_id": merchant_id}
    token = create_access_token(
        data=qr_data,
        expires_delta=timedelta(seconds=QR_TOKEN_EXPIRE_SECONDS)
    )
    return {"qr_token": token, "expires_in": QR_TOKEN_EXPIRE_SECONDS}

@app.put("/api/customer/pin")
def change_customer_pin(data: PinUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Cambiar PIN del cliente"""
    if current_user.role != "customer":
        raise HTTPException(status_code=403, detail="Solo clientes pueden cambiar PIN")
    
    customer = db.query(Customer).filter(Customer.user_id == current_user.id).first()
    if not customer or not verify_password(data.old_pin, customer.pin):
        raise HTTPException(status_code=400, detail="PIN actual incorrecto")
    
    if not data.new_pin.isdigit() or len(data.new_pin) != 4:
        raise HTTPException(status_code=400, detail="Nuevo PIN debe ser 4 dígitos")
    
    customer.pin = get_password_hash(data.new_pin)
    db.commit()
    return {"message": "PIN actualizado"}

# ================= RUTAS COMERCIO =================
@app.post("/api/merchant/branch")
def create_branch(data: BranchCreate, current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Crear sucursal"""
    branch = Branch(
        merchant_id=current_user.id,
        branch_name=data.branch_name,
        location=data.location,
        stamps_valid_all_branches=data.stamps_valid_all_branches
    )
    db.add(branch)
    db.commit()
    return {"id": branch.id, "message": "Sucursal creada"}

@app.get("/api/merchant/branches")
def get_branches(current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Ver sucursales del comercio"""
    branches = db.query(Branch).filter(Branch.merchant_id == current_user.id).all()
    return [
        {
            "id": b.id,
            "name": b.branch_name,
            "location": b.location,
            "stamps_valid_all": b.stamps_valid_all_branches
        }
        for b in branches
    ]

@app.post("/api/merchant/scan")
def scan_qr(qr_token: str, current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Escanear QR y agregar sello"""
    try:
        payload = jwt.decode(qr_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "qr_stamp":
            raise HTTPException(status_code=400, detail="QR inválido")
    except JWTError:
        raise HTTPException(status_code=400, detail="QR expirado o inválido")

    customer_id = payload.get("user_id")
    merchant_id = payload.get("merchant_id") or current_user.id

    # Obtener config actual del comercio
    merchant_config = db.query(MerchantConfig).filter(
        MerchantConfig.merchant_id == current_user.id
    ).first()
    current_max_stamps = merchant_config.max_stamps if hasattr(merchant_config, 'max_stamps') else 10

    # Obtener o crear tarjeta del cliente
    card = db.query(CustomerMerchant).filter(
        CustomerMerchant.customer_id == customer_id,
        CustomerMerchant.merchant_id == merchant_id
    ).first()

    if not card:
        card = CustomerMerchant(
            customer_id=customer_id,
            merchant_id=merchant_id,
            max_stamps=current_max_stamps  # ← GUARDAR max_stamps actual
        )
        db.add(card)
        db.flush()

    card.stamps += 1
    db.add(Transaction(merchant_id=current_user.id, customer_id=customer_id))

    if card.stamps >= card.max_stamps:  # ← USAR max_stamps de la tarjeta
        reward = db.query(Reward).filter(
            Reward.merchant_id == current_user.id,
            Reward.stamps_required == card.max_stamps
        ).first()
        
        if reward:
            coupon = Coupon(
                customer_id=customer_id,
                merchant_id=current_user.id,
                reward_id=reward.id
            )
            db.add(coupon)
            card.stamps = 0

    db.commit()
    
    customer = db.query(User).filter(User.id == customer_id).first()
    return {
        "message": "¡Sello añadido!",
        "customer_email": customer.email if customer else "desconocido",
        "new_total": card.stamps,
        "max_stamps": card.max_stamps
    }

@app.post("/api/merchant/add-stamp-dni")
def add_stamp_dni(email: str, current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Agregar sello usando email del cliente"""
    customer_user = db.query(User).filter(User.email == email, User.role == "customer").first()
    if not customer_user:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    # Obtener config actual del comercio
    merchant_config = db.query(MerchantConfig).filter(
        MerchantConfig.merchant_id == current_user.id
    ).first()
    current_max_stamps = merchant_config.max_stamps if merchant_config and hasattr(merchant_config, 'max_stamps') else 10

    card = db.query(CustomerMerchant).filter(
        CustomerMerchant.customer_id == customer_user.id,
        CustomerMerchant.merchant_id == current_user.id
    ).first()

    if not card:
        card = CustomerMerchant(
            customer_id=customer_user.id,
            merchant_id=current_user.id,
            max_stamps=current_max_stamps  # ← GUARDAR max_stamps actual
        )
        db.add(card)
        db.flush()

    card.stamps += 1
    db.add(Transaction(merchant_id=current_user.id, customer_id=customer_user.id))

    if card.stamps >= card.max_stamps:  # ← USAR max_stamps de la tarjeta
        reward = db.query(Reward).filter(
            Reward.merchant_id == current_user.id,
            Reward.stamps_required == card.max_stamps
        ).first()
        
        if reward:
            coupon = Coupon(
                customer_id=customer_user.id,
                merchant_id=current_user.id,
                reward_id=reward.id
            )
            db.add(coupon)
            card.stamps = 0

    db.commit()

    return {
        "message": "¡Sello añadido!",
        "customer_email": customer_user.email,
        "new_total": card.stamps,
        "max_stamps": card.max_stamps
    }

@app.post("/api/merchant/add-stamp-dni-dashboard")
def add_stamp_dni_dashboard(dni: str, current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Agregar sello usando DNI del cliente (desde dashboard)"""
    if not dni or len(dni.strip()) == 0:
        raise HTTPException(status_code=400, detail="DNI requerido")
    
    customer = db.query(Customer).filter(Customer.dni == dni).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Cliente con ese DNI no encontrado")
    
    customer_user = db.query(User).filter(User.id == customer.user_id).first()
    if not customer_user:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    # Obtener config actual del comercio
    merchant_config = db.query(MerchantConfig).filter(
        MerchantConfig.merchant_id == current_user.id
    ).first()
    current_max_stamps = merchant_config.max_stamps if hasattr(merchant_config, 'max_stamps') else 10

    card = db.query(CustomerMerchant).filter(
        CustomerMerchant.customer_id == customer_user.id,
        CustomerMerchant.merchant_id == current_user.id
    ).first()

    if not card:
        card = CustomerMerchant(
            customer_id=customer_user.id,
            merchant_id=current_user.id,
            max_stamps=current_max_stamps  # ← GUARDAR max_stamps actual
        )
        db.add(card)
        db.flush()

    card.stamps += 1
    db.add(Transaction(merchant_id=current_user.id, customer_id=customer_user.id))

    if card.stamps >= card.max_stamps:  # ← USAR max_stamps de la tarjeta
        reward = db.query(Reward).filter(
            Reward.merchant_id == current_user.id,
            Reward.stamps_required == card.max_stamps
        ).first()
        
        if reward:
            coupon = Coupon(
                customer_id=customer_user.id,
                merchant_id=current_user.id,
                reward_id=reward.id
            )
            db.add(coupon)
            card.stamps = 0

    db.commit()

    return {
        "message": "¡Sello añadido!",
        "customer_email": customer_user.email,
        "customer_dni": dni,
        "new_total": card.stamps,
        "max_stamps": card.max_stamps
    }

# Nueva ruta para actualizar max_stamps del comercio
@app.put("/api/merchant/max-stamps")
def update_merchant_max_stamps(data: MerchantMaxStampsUpdate, current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Actualizar max_stamps para nuevas tarjetas del comercio"""
    config = db.query(MerchantConfig).filter(
        MerchantConfig.merchant_id == current_user.id
    ).first()
    
    if not config:
        config = MerchantConfig(merchant_id=current_user.id)
        db.add(config)
    
    config.max_stamps = data.max_stamps
    db.commit()
    return {
        "message": "Configuración de sellos actualizada",
        "max_stamps": config.max_stamps,
        "note": "Las nuevas tarjetas usarán esta configuración. Las tarjetas existentes mantienen su configuración actual."
    }

@app.get("/api/merchant/max-stamps")
def get_merchant_max_stamps(current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Obtener max_stamps actual del comercio"""
    config = db.query(MerchantConfig).filter(
        MerchantConfig.merchant_id == current_user.id
    ).first()
    
    if not config:
        return {"max_stamps": 10}
    
    return {"max_stamps": getattr(config, 'max_stamps', 10)}

@app.get("/api/merchant/dashboard")
def merchant_dashboard(current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
    """Dashboard del comercio"""
    rewards = db.query(Reward).filter(Reward.merchant_id == current_user.id).all()
    coupons_total = db.query(Coupon).filter(Coupon.merchant_id == current_user.id).count()
    coupons_redeemed = db.query(Coupon).filter(
        Coupon.merchant_id == current_user.id,
        Coupon.redeemed == 1
    ).count()
    transactions_count = db.query(Transaction).filter(Transaction.merchant_id == current_user.id).count()

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
    """Cupones generados por el comercio"""
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
            })
    
    return result

@app.put("/api/merchant/coupon/{coupon_id}/redeem")
def redeem_coupon(coupon_id: int, current_user: User = Depends(get_merchant_user), db: Session = Depends(get_db)):
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

# ================= RUTAS ADMIN =================
@app.get("/api/admin/merchants")
def admin_merchants(current_user: User = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Ver TODOS los comercios (solo admin)"""
    merchants = db.query(User).filter(User.role == "merchant").all()
    result = []
    
    for merchant in merchants:
        transactions = db.query(Transaction).filter(Transaction.merchant_id == merchant.id).count()
        result.append({
            "id": merchant.id,
            "email": merchant.email,
            "business_name": merchant.business_name,
            "transactions": transactions
        })
    
    return result

@app.get("/api/admin/config")
def get_admin_config(db: Session = Depends(get_db)):
    config = db.query(Config).first()
    if not config:
        config = Config(max_stamps=10)
        db.add(config)
        db.commit()
    return {"max_stamps": config.max_stamps, "reward_description": config.reward_description}

@app.put("/api/admin/config")
def update_admin_config(max_stamps: int, current_user: User = Depends(get_admin_user), db: Session = Depends(get_db)):
    """Actualizar max_stamps global"""
    config = db.query(Config).first()
    if not config:
        config = Config(max_stamps=max_stamps)
        db.add(config)
    else:
        config.max_stamps = max_stamps
    db.commit()
    return {"message": "Configuración actualizada", "max_stamps": config.max_stamps}

# ================= RUTAS ESTÁTICAS =================
@app.get("/")
async def read_root():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
    return FileResponse(html_path) if os.path.exists(html_path) else {"error": "index.html no encontrado"}

@app.get("/merchant-dashboard")
async def merchant_dashboard_page():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "merchant-dashboard.html")
    return FileResponse(html_path) if os.path.exists(html_path) else {"error": "archivo no encontrado"}

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.get("/debug/config")
def debug_config(db: Session = Depends(get_db)):
    """Debug: Ver configuración actual"""
    config = db.query(Config).first()
    if not config:
        return {"error": "No hay config"}
    return {
        "id": config.id,
        "max_stamps": config.max_stamps,
        "reward_description": config.reward_description
    }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)  # Ya está correcto, acepta todas las IPs