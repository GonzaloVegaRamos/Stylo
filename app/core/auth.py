import os
from fastapi import HTTPException, Depends
from app.db.database import get_supabase_client
from fastapi.security import OAuth2PasswordBearer

# Cargar las variables de entorno
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="users/login")

# Obtener cliente de Supabase
supabase = get_supabase_client()

# Función para verificar el token JWT y obtener los datos del usuario autenticado
def authenticate_token(token: str = Depends(oauth2_scheme)):
    try:
        # Verificar el token con Supabase
        user_data = supabase.auth.api.get_user(token)
        
        if not user_data:
            raise HTTPException(
                status_code=401,
                detail="Token inválido o expirado",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Si el token es válido, devolvemos los datos del usuario
        return user_data["user"]
    except Exception as e:
        raise HTTPException(
            status_code=401,
            detail="Token inválido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
