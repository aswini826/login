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

router = APIRouter(
    prefix='/login',
    tags=['login']
)

session = SessionLocal()

SECRET_KEY = 'nothingnothinggosaveusnow'
ALGORITHM = 'HS256'


bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')


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
    access_token: str
    token_type: str
    message: str


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


def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


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
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.', headers={"WWW-Authenticate": "Bearer"})

    token = create_access_token(user.username, user.id, timedelta(minutes=20))
    return {'access_token': token, 'token_type': 'bearer', 'message': 'Login Successfully'}


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


