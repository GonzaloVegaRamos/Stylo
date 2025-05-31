from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.endpoints import users
from app.db.database import get_supabase_client

# Crear la aplicación FastAPI
app = FastAPI()

# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files (para imágenes, CSS, JS...)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Jinja2 templates (para HTML)
templates = Jinja2Templates(directory="templates")

# Supabase
supabase = get_supabase_client()

# Rutas
app.include_router(users.router, prefix="/users", tags=["users"])

@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/Guia-Estilo", response_class=HTMLResponse)
def read_guia(request: Request):
    return templates.TemplateResponse("guia.html", {"request": request})

@app.get("/armario", response_class=HTMLResponse)
async def read_armario(request: Request):
    return templates.TemplateResponse("armario.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("Register.html", {"request": request})


@app.get("/crear-conjunto", response_class=HTMLResponse)
async def crear_conjunto_page(request: Request):
    return templates.TemplateResponse("crear-conjunto.html", {"request": request})


@app.get("/ver-conjunto", response_class=HTMLResponse)
async def ver_conjunto_page(request: Request):
    return templates.TemplateResponse("view-conjunto.html", {"request": request})

@app.get("/comunidad", response_class=HTMLResponse)
async def comunidad_page(request: Request):
    return templates.TemplateResponse("comunidad.html", {"request": request})

@app.get("/auth/callback", response_class=HTMLResponse)
async def callback_page(request: Request):
    return templates.TemplateResponse("callback.html", {"request": request})
