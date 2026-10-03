import asyncio
import logging

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from infra_assessor.app.dependencies import session_scope
from infra_assessor.app.main import app
from infra_assessor.storage.models import Base
from infra_assessor.web import routes


@pytest.fixture
def web_database():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)

    def override_session():
        with Session(engine, expire_on_commit=False) as session:
            yield session

    app.dependency_overrides[session_scope] = override_session
    yield
    app.dependency_overrides.clear()
    routes.tasks.clear()
    engine.dispose()


@pytest.mark.asyncio
async def test_create_assessment_schedules_task_redirects_and_removes_it(
    web_database, monkeypatch
) -> None:
    started = asyncio.Event()
    finish = asyncio.Event()

    async def assessment_execution(assessment_id: str) -> None:
        started.set()
        await finish.wait()

    monkeypatch.setattr(routes, "execute_assessment", assessment_execution)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/assessments",
            data={
                "customer_name": "Acme",
                "target_cidr": "192.168.1.0/24",
                "authorised": "yes",
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    assessment_id = response.headers["location"].removeprefix("/assessments/")
    await asyncio.wait_for(started.wait(), timeout=1)
    assert assessment_id in routes.tasks
    assert not routes.tasks[assessment_id].done()

    finish.set()
    await asyncio.wait_for(routes.tasks[assessment_id], timeout=1)
    await asyncio.sleep(0)
    assert assessment_id not in routes.tasks


@pytest.mark.asyncio
async def test_assessment_task_failure_is_retrieved_without_crashing_app(
    web_database, monkeypatch, caplog
) -> None:
    async def failed_execution(assessment_id: str) -> None:
        raise RuntimeError("background failure")

    monkeypatch.setattr(routes, "execute_assessment", failed_execution)
    caplog.set_level(logging.ERROR, logger=routes.__name__)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/assessments",
            data={
                "customer_name": "Acme",
                "target_cidr": "10.0.0.0/24",
                "authorised": "yes",
            },
            follow_redirects=False,
        )
        await asyncio.sleep(0)

        # The application remains available after a background execution failure.
        dashboard = await client.get("/")

    assert response.status_code == 303
    assert dashboard.status_code == 200
    assert not routes.tasks
    assert "Unhandled assessment task failure" in caplog.text
