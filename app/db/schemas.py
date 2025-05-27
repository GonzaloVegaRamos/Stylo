from pydantic import BaseModel, ConfigDict
from typing import Optional
from uuid import UUID


class UserCreate(BaseModel):
    email: str
    password: Optional[str] = None
    username: str
    gender: Optional[str] = None
    style_preference: Optional[str] = None
    edad: int
    is_google_account: Optional[bool] = False

    model_config = ConfigDict(from_attributes=True)

class GoogleUserCreate(BaseModel):
    id: str
    email: str
    full_name: Optional[str]
    model_config = ConfigDict(from_attributes=True)


class UserLogin(BaseModel):
    email: str
    password: str

    model_config = ConfigDict(from_attributes=True)


class UserResponse(BaseModel):
    id: UUID
    email: str
    username: str
    gender: Optional[str] = None
    style_preference: Optional[str] = None
    edad: int
    is_google_account: Optional[bool] = False

    model_config = ConfigDict(from_attributes=True)


class ConjuntoCreate(BaseModel):
    nombre: str
    camiseta: Optional[UUID] = None
    ral: Optional[UUID] = None
    pb: Optional[UUID] = None
    calzado: Optional[UUID] = None
    accesorio: Optional[UUID] = None
    chaqueta: Optional[UUID] = None
    usuario: Optional[int] = None
    codigo : Optional [UUID] = None
    estilo : Optional [str] = None

    model_config = ConfigDict(from_attributes=True)




