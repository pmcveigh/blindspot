from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from infra_assessor.app.config import settings

from .models import Base

engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(engine, expire_on_commit=False)


def initialise_database() -> None:
    Base.metadata.create_all(engine)
    # SQLite create_all does not add columns. These nullable/defaulted additions keep
    # databases created by v0.1.0 usable without a migration framework.
    additions = {
        "assessments": {
            "assessment_level": "VARCHAR(40) DEFAULT 'active_identification'",
            "elapsed_seconds": "FLOAT",
            "addresses_in_target": "INTEGER",
            "responding_hosts": "INTEGER",
            "services_discovered": "INTEGER",
            "findings_count": "INTEGER",
        },
        "devices": {"classification_evidence": "TEXT"},
        "services": {
            "identification_confidence": "VARCHAR(20) DEFAULT 'unknown'",
            "identification_source": "VARCHAR(255)",
            "identified_protocol": "VARCHAR(50)",
            "evidence_state": "VARCHAR(20) DEFAULT 'inferred'",
            "probe_evidence": "TEXT",
        },
    }
    with engine.begin() as connection:
        inspector = inspect(connection)
        for table, columns in additions.items():
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, sql_type in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))


def session_scope():  # type annotation avoided: generator context is consumed by FastAPI
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
