from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    admin_email: str
    admin_fullname: str
    admin_password: str
    
    db_host: str
    db_port: int
    db_name: str
    db_user: str
    db_password: str
    
    redis_host: str
    redis_port: int

    random_secret: str

    model_config = SettingsConfigDict(
        env_file=".env", 
        case_sensitive=False
    )

    @property
    def database_url(self) -> str:
        return f"postgresql+asyncpg://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

settings = Settings()