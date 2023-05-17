from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import models
from database import engine
from routers import auth

app = FastAPI()

origins = [
    "http://localhost:4200"
]

app.add_middleware(
  CORSMiddleware,
  allow_origins=origins,
  allow_credentials=True,
  allow_methods=["*"],
  allow_headers=["*"],
)


models.Base.metadata.create_all(bind=engine)

app.include_router(auth.router)


