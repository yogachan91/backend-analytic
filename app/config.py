from dotenv import load_dotenv
import os
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "5"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "changeme_in_production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
INTERNAL_KEY = os.getenv("INTERNAL_KEY", "default_secret_kalo_env_ga_ada")
# SERVICE_URL = os.getenv("SERVICE_URL", "http://192.168.33.91:8000")
# SERVICE_URL = os.getenv("SERVICE_URL", "http://100.68.97.7:8000")
SERVICE_URL = os.getenv("SERVICE_URL", "http://10.100.21.235:8000")
