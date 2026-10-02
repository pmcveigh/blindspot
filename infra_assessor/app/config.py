from pathlib import Path

from pydantic import BaseModel


class Settings(BaseModel):
    data_dir: Path = Path.home() / ".local" / "share" / "infra-assessor"
    host: str = "127.0.0.1"
    port: int = 8462

    @property
    def database_url(self) -> str:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{self.data_dir / 'assessments.db'}"


settings = Settings()
