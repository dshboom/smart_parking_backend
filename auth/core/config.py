# /core/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    ADMIN_USERNAME: str | None = None
    ADMIN_PASSWORD: str | None = None
    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()