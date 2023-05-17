from fastapi import FastAPI
import models
from database import engine
from routers import auth, users

app = FastAPI()

origins = [
    "http://localhost:4200"
]

app.add_middleware (
  CORSMiddleware,
  allow_origins=origins,
  allow_credentials=True,
  allow_methods=["*"],
  allow_headers=["*"],
)

models.Base.metadata.create_all(bind=engine)

app.include_router(auth.router)


