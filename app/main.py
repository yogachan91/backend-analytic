from fastapi import FastAPI
from .database import engine
from . import models
from .routers import auth_routes, elastic_routes, countip_routes
from fastapi.middleware.cors import CORSMiddleware

# create tables if not exist (quick setup)
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="FastAPI JWT + Proxy Elastic")

app.add_middleware(
    CORSMiddleware,
    # allow_origins=["http://192.168.33.91:3000"],  # atur ke domain anda di production
    # allow_origins=["http://100.68.97.7:3000"],  # atur ke domain anda di production
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router)
app.include_router(elastic_routes.router)
app.include_router(countip_routes.router)
