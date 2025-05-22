from supabase import create_client, Client
import os
from dotenv import load_dotenv

# Cargar las variables de entorno para obtener la URL y la clave de Supabase
load_dotenv()

supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

# Crear el cliente de Supabase
supabase: Client = create_client(supabase_url, supabase_key)

def get_supabase_client():
    return supabase
