
from app.db.database import get_supabase_client  # Esto importa tu cliente de Supabase (si lo necesitas)

# Crear el motor de base de datos para SQLAlchemy
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"  # O la URL de tu base de datos
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

# Crear una clase base para todos los modelos
Base = declarative_base()

# Crear una sesión de base de datos
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependencia para obtener la sesión de base de datos
def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db  # Genera la sesión para cada solicitud
    finally:
        db.close()  # Cierra la sesión al finalizar
