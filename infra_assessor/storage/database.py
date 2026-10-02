from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from infra_assessor.app.config import settings

from .models import Base

engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def initialise_database() -> None:
    Base.metadata.create_all(engine)


def session_scope():  # type annotation avoided: generator context is consumed by FastAPI
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
