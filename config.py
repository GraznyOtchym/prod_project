from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    admin_email: str
    admin_fullname: str
    admin_password: str

    db_host: str = "db"
    db_port: int = 5432
    db_name: str = "anti_fraud"
    db_user: str = "postgres"
    db_password: str = "postgres"

    redis_host: str = "redis"
    redis_port: int = 6379

    random_secret: str = Field(..., min_length=128, max_length=128)

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False)

    @property
    def database_url(self) -> str:
        return f"postgresql+asyncpg://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"


settings = Settings()
