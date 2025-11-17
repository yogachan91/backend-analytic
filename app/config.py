from dotenv import load_dotenv
import os
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "changeme_in_production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
EXTERNAL_ELASTIC_BASE = os.getenv("EXTERNAL_ELASTIC_BASE", "http://103.150.227.205:8000")
