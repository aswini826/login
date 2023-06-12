from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

SQLALCHEMY_DATABASE_URL = 'postgresql://meesho_database_user:ULIy8uA31KR3EXIFRBFeBwDnC23wGNXN@dpg-ci3cctbhp8u1a1f58m1g-a.oregon-postgres.render.com/meesho_database'


engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
