import asyncio
import logging
from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from infra_assessor.app.dependencies import DatabaseSession
from infra_assessor.intelligence.engine import generate_findings
from infra_assessor.intelligence.rules import load_rules
from infra_assessor.reporting.generator import render_pdf, render_report
from infra_assessor.scanner.base import ScanCancelled, ScannerError
from infra_assessor.scanner.nmap import NmapScanner, validate_target
from infra_assessor.storage.database import SessionLocal
from infra_assessor.storage.repository import Repository

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).with_name("templates"))
logger = logging.getLogger(__name__)
tasks: dict[str, asyncio.Task[None]] = {}


def _assessment_task_done(assessment_id: str, task: asyncio.Task[None]) -> None:
    """Remove a finished task and retrieve any exception it returned."""
    tasks.pop(assessment_id, None)
    if task.cancelled():
        return
    try:
        task.result()
    except Exception:
        # execute_assessment handles normal failures and records them in the database.
        # This is a final safeguard for failures in that error-handling path.
        logger.exception("Unhandled assessment task failure: %s", assessment_id)


async def execute_assessment(assessment_id: str) -> None:
    session = SessionLocal()
    repo = Repository(session)
    try:
        assessment = repo.get_assessment(assessment_id)
        if not assessment:
            return
        repo.start(assessment_id)
        result = await NmapScanner().scan(assessment.target_cidr)
        repo.save_result(assessment_id, result, generate_findings(result, load_rules()))
    except ScanCancelled as exc:
        repo.fail(assessment_id, str(exc), "cancelled")
    except (ScannerError, OSError, ValueError) as exc:
        logger.warning("Assessment %s stopped: %s", assessment_id, exc)
        repo.fail(assessment_id, str(exc))
    except Exception:
        logger.exception("Unexpected assessment failure: %s", assessment_id)
        repo.fail(assessment_id, "An unexpected local processing or database error occurred.")
    finally:
        session.close()


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: DatabaseSession):
    repo = Repository(db)
    rows = [(a, *repo.counts(a.id)) for a in repo.list_assessments()]
    return templates.TemplateResponse(request, "dashboard.html", {"rows": rows})


@router.get("/assessments/new", response_class=HTMLResponse)
def new_assessment(request: Request):
    return templates.TemplateResponse(request, "new.html", {})


@router.post("/assessments")
async def create_assessment(
    request: Request,
    db: DatabaseSession,
    customer_name: str = Form(...),
    target_cidr: str = Form(...),
    authorised: str | None = Form(None),
):
    error = None
    if not authorised:
        error = "You must confirm that you are authorised to assess this network."
    elif not customer_name.strip():
        error = "Customer name is required."
    try:
        target = validate_target(target_cidr)
    except ValueError as exc:
        error, target = str(exc), target_cidr
    if error:
        return templates.TemplateResponse(
            request,
            "new.html",
            {"error": error, "customer_name": customer_name, "target_cidr": target_cidr},
            status_code=422,
        )
    item = Repository(db).create_assessment(customer_name, target)
    task = asyncio.create_task(execute_assessment(item.id))
    tasks[item.id] = task
    task.add_done_callback(lambda completed: _assessment_task_done(item.id, completed))
    return RedirectResponse(f"/assessments/{item.id}", status_code=303)


@router.get("/assessments/{assessment_id}", response_class=HTMLResponse)
def assessment(request: Request, assessment_id: str, db: DatabaseSession):
    item = Repository(db).get_assessment(assessment_id)
    if not item:
        raise HTTPException(404)
    name = "progress.html" if item.status in {"pending", "running"} else "results.html"
    return templates.TemplateResponse(request, name, {"assessment": item})


@router.post("/assessments/{assessment_id}/cancel")
def cancel(assessment_id: str):
    if task := tasks.get(assessment_id):
        task.cancel()
    return RedirectResponse(f"/assessments/{assessment_id}", status_code=303)


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device(request: Request, device_id: str, db: DatabaseSession):
    repo = Repository(db)
    item = repo.get_device(device_id)
    if not item:
        raise HTTPException(404)
    return templates.TemplateResponse(
        request, "device.html", {"device": item, "findings": repo.device_findings(device_id)}
    )


@router.get("/assessments/{assessment_id}/report", response_class=HTMLResponse)
def html_report(assessment_id: str, db: DatabaseSession):
    item = Repository(db).get_assessment(assessment_id)
    if not item:
        raise HTTPException(404)
    return HTMLResponse(render_report(item))


@router.get("/assessments/{assessment_id}/report.pdf")
async def pdf_report(assessment_id: str, db: DatabaseSession):
    item = Repository(db).get_assessment(assessment_id)
    if not item:
        raise HTTPException(404)
    try:
        content = await render_pdf(render_report(item))
    except RuntimeError as exc:
        raise HTTPException(503, detail=str(exc)) from exc
    return Response(
        content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="assessment-{assessment_id}.pdf"'},
    )
