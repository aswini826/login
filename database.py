from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

SQLALCHEMY_DATABASE_URL = 'postgresql://meesho_user:oq6atqUb5uZZM1QbpFFQuXQqQWO9nRDs@dpg-ci3arhu7avj2t30374lg-a.oregon-postgres.render.com/meesho'


engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
