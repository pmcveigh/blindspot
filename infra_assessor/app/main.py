import logging
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from infra_assessor.app.config import settings
from infra_assessor.storage.database import initialise_database
from infra_assessor.web.routes import router

app = FastAPI(title="Infra Assessor", version="0.1.0", docs_url=None, redoc_url=None)
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
app.mount("/static", StaticFiles(directory=PACKAGE_ROOT / "web" / "static"), name="static")
app.include_router(router)


@app.on_event("startup")
def startup() -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=settings.data_dir / "infra-assessor.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    initialise_database()


def run() -> None:
    uvicorn.run("infra_assessor.app.main:app", host=settings.host, port=settings.port)
