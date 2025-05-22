from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware  # Importar CORSMiddleware
from app.api.v1.endpoints import users
from app.db import models, database
from app.db.database import get_supabase_client

from app.db import crud, schemas

# Crear la aplicación FastAPI
app = FastAPI()

# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permitir solicitudes desde cualquier origen
    allow_credentials=True,
    allow_methods=["*"],  # Permitir todos los métodos HTTP (GET, POST, etc.)
    allow_headers=["*"],  # Permitir todos los headers
)

supabase = get_supabase_client()

# Incluir las rutas de usuarios en la API con el prefijo '/users'
app.include_router(users.router, prefix="/users", tags=["users"])

# Ruta raíz de ejemplo
@app.get("/")
def read_root():
    return {"message": "Welcome to the User Management API!"}
