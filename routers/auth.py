from datetime import timedelta, datetime, date
from typing_extensions import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field, validator
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from cryptography.fernet import Fernet

router = APIRouter(
    prefix='/login',
    tags=['login']
)

session = SessionLocal()

SECRET_KEY = 'nothingnothinggosaveusnow'
ALGORITHM = 'HS256'

ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

refresh_tokens = {}

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

revoked_tokens = set()

secret_key = Fernet.generate_key()
cipher_suite = Fernet(secret_key)


class CreateUserRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    confirm_password: str
    register_number: int
    phone: str
    date_of_birth: date
    course: str

    @validator('password')
    def password_must_be_strong(cls, value):
        if not (8 <= len(value) <= 50):
            raise ValueError('Password must be between 8 and 50 characters long')
        return value


class Login(BaseModel):
    username_or_email: str
    password: str


class Token(BaseModel):
    refresh_token: str
    access_token: str


class PasswordUpdate(BaseModel):
    username_or_email: str = Field(..., alias="username_or_email")
    new_password: str = Field(..., alias="newPassword")
    confirm_password: str = Field(..., alias="confirmPassword")

    @validator('username_or_email')
    def username_or_email_must_valid(cls, value):
        if '@' in value:
            email = EmailStr(value)
            return email
        else:
            if not (4 <= len(value) <= 20):
                raise ValueError('Username must be between 4 and 20 characters long')
            return value

    @validator('new_password')
    def password_must_be_strong(cls, value):
        if not (8 <= len(value) <= 50):
            raise ValueError('Password must be between 8 and 50 characters long')
        return value


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def authenticate_user(username_or_email: str, password: str, db):
    user = db.query(Users).filter(Users.username == username_or_email).first()
    if not user:
        user = db.query(Users).filter(Users.email == username_or_email).first()
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect username or email")
    if not bcrypt_context.verify(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect password")
    return user


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt


def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not validate user.')
        return {'username': username, 'id': user_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


@router.post("/auth", status_code=status.HTTP_201_CREATED)
def create_user(db: db_dependency,
                create_user_request: CreateUserRequest):
    if db.query(Users).filter(Users.username == create_user_request.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(Users).filter(Users.email == create_user_request.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    if create_user_request.password != create_user_request.confirm_password:
        raise HTTPException(status_code=400, detail="Password and confirm password should be same")

    create_user_model = Users(
        email=create_user_request.email,
        username=create_user_request.username,
        hashed_password=bcrypt_context.hash(create_user_request.password),
        register_number=create_user_request.register_number,
        phone=create_user_request.phone,
        date_of_birth=create_user_request.date_of_birth,
        course=create_user_request.course
    )

    db.add(create_user_model)
    db.commit()
    db.refresh(create_user_model)
    return {"message": "User created Successfully"}


@router.post("/token", response_model=Token)
def login_for_access_token(login_request: Login,
                           db: db_dependency):
    user = authenticate_user(login_request.username_or_email, login_request.password, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token({"sub": user.username}, access_token_expires)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = create_access_token({"sub": user.username}, refresh_token_expires)
    return {"access_token": access_token, "refresh_token": refresh_token}


@router.get("/protected")
def protected_route(current_user: Users = Depends(get_current_user)):
    return {"message": f"Welcome, {current_user.username}!"}


@router.put("/update_password")
async def update_user_password(update_password: PasswordUpdate,
                               db: db_dependency):
    user = db.query(Users).filter(
        (Users.email == update_password.username_or_email) |
        (Users.username == update_password.username_or_email)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if update_password.new_password != update_password.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="New password and confirm password should be same")

    new_hashed_password = bcrypt_context.hash(update_password.new_password)
    user.hashed_password = new_hashed_password
    db.commit()
    return {'message': 'Password changed Successfully'}


@router.get("/users", status_code=status.HTTP_200_OK)
async def get_users(db: db_dependency):
    return db.query(Users).all()


@router.delete('/delete_user/{user_id}')
def delete_user(user_id: int, db: db_dependency):
    user = db.query(Users).filter(Users.id == user_id).first()
    db.delete(user)
    db.commit()
    return {'message': 'User deleted Successfully'}


@router.post("/encrypt")
def encrypt(data: str):
    # Convert the data to bytes
    data_bytes = data.encode()

    # Encrypt the data using the cipher suite
    encrypted_data = cipher_suite.encrypt(data_bytes)

    # Return the encrypted data
    return {"encrypted_data": encrypted_data}


@router.post("/decrypt")
def decrypt(encrypted_data: str):
    # Decrypt the encrypted data using the cipher suite
    decrypted_data = cipher_suite.decrypt(encrypted_data.encode())

    # Convert the decrypted data to a string
    decrypted_data_str = decrypted_data.decode()

    # Return the decrypted data
    return {"decrypted_data": decrypted_data_str}


def remove_tokens(user_id):
    pass


@router.post("/logout/all")
def logout_all_devices(user_id: int):
    # Remove the user's access token and refresh token from the storage
    # based on their user_id
    remove_tokens(user_id)

    return {"message": "Logged out from all devices successfully."}
