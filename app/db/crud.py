from app.db.database import get_supabase_client  # Usamos el cliente de Supabase
from app.db.schemas import UserCreate  # Usamos el esquema de Pydantic
from passlib.context import CryptContext  # Para encriptar contraseñas

# Configuración de encriptación de contraseñas (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Crear el cliente de Supabase
supabase = get_supabase_client()

# Función para obtener un usuario por su email
def get_user_by_email(email: str):
    response = supabase.table('users').select('*').eq('email', email).execute()
    return response.data[0] if response.data else None

# Función para crear un nuevo usuario
def create_user(user: UserCreate):
    # Encriptar la contraseña
    hashed_password = pwd_context.hash(user.password)
    
    # Crear un nuevo usuario en la base de datos
    new_user = {
        "email": user.email,
        "password": hashed_password,
        "username": user.username,
        "gender": user.gender,
        "style_preference": user.style_preference,
        "edad": user.edad
    }
    
    # Insertar el usuario en la base de datos
    response = supabase.table('users').insert(new_user).execute()
    
    # Retornar el usuario creado (o el primer dato de la respuesta)
    return response.data[0] if response.data else None
