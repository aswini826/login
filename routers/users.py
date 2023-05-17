from typing import Annotated
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, Path, HTTPException
from starlette import status
from models import Login
from database import SessionLocal
from .auth import get_current_user

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[Session, Depends(get_current_user)]


class LoginRequest(BaseModel):
    email: str
    hashed_password: str


@router.get("/")
def read_all(db: Annotated[Session, Depends(get_db)]):
    return db.query(Login).all()


@router.get("/login/{login_email}", status_code=status.HTTP_200_OK)
def read_login(db: db_dependency, login_id: int = Path(gt=0)):
    login_model = db.query(Login).filter(Login.id == login_id).first()
    if login_model is not None:
        return login_model
    raise HTTPException(status_code=404, detail='Login email not found')


@router.post("/login", status_code=status.HTTP_201_CREATED)
def create_login(user: user_dependency,
                 db: db_dependency,
                 login_request: LoginRequest):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    login_model = Login(**login_request.dict(), owner_id=user.get('id'))

    db.add(login_model)
    db.commit()



@router.put("/login/{login_id}", status_code=status.HTTP_204_NO_CONTENT)
def update_login(db: db_dependency,
                 login_request: LoginRequest,
                 login_id: int = Path(gt=0)):
    login_model = db.query(Login).filter(Login.id == login_id).first()
    if login_model is None:
        raise HTTPException(status_code=404, detail='Login email not found')

    login_model.email = login_request.email
    login_model.hashed_password = login_request.hashed_password

    db.add(login_model)
    db.commit()


@router.delete("login/{login_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_login(db: db_dependency, login_id: int = Path(gt=0)):
    login_model = db.query(Login).filter(Login.id == login_id).first()
    if login_model is None:
        raise HTTPException(status_code=404, detail='Login email not Found')
    db.query(Login).filter(Login.id == login_id).delete()

    db.commit()
