from typing_extensions import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users

router = APIRouter(
    prefix='/Meesho API',
    tags=['Meesho']
)

session = SessionLocal()


class CreateUserRequest(BaseModel):
    product_name: str
    description: str
    price: int
    quantity: int
    seller_id: int


class UpdateProductDetails(BaseModel):
    product_name: str
    description: str
    price: int
    quantity: int
    seller_id: int


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


@router.post("/auth", status_code=status.HTTP_201_CREATED)
def create_user(db: db_dependency,
                create_user_request: CreateUserRequest):
    if db.query(Users).filter(Users.product_name == create_user_request.product_name).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    create_user_model = Users(
        product_name=create_user_request.product_name,
        description=create_user_request.description,
        price=create_user_request.price,
        quantity=create_user_request.quantity,
        seller_id=create_user_request.seller_id
    )

    db.add(create_user_model)
    db.commit()
    db.refresh(create_user_model)
    return {"message": "User created Successfully"}


@router.put("/update_details")
async def update_user_password(update_details: UpdateProductDetails,
                               db: db_dependency):
    user = db.query(Users).filter(Users.seller_id == update_details.seller_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="This seller are already exists")

    db.commit()
    return {'message': 'Products changed Successfully'}


@router.get("/users", status_code=status.HTTP_200_OK)
async def get_users(db: db_dependency):
    return db.query(Users).all()


@router.delete('/delete_user/{user_id}')
def delete_user(user_id: int, db: db_dependency):
    user = db.query(Users).filter(Users.id == user_id).first()
    db.delete(user)
    db.commit()
    return {'message': 'User deleted Successfully'}
