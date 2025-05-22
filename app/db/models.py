from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

# Crear la base de datos declarativa
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    username = Column(String)
    gender = Column(String, nullable=True)
    style_preference = Column(String, nullable=True)
    edad = Column(Integer)
