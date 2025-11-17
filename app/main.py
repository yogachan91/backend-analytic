from fastapi import FastAPI
from .database import engine
from . import models
from .routers import auth_routes, elastic_routes
from fastapi.middleware.cors import CORSMiddleware

# create tables if not exist (quick setup)
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="FastAPI JWT + Proxy Elastic")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # atur ke domain anda di production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router)
app.include_router(elastic_routes.router)
