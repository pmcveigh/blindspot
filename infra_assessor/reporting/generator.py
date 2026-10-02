from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from playwright.async_api import async_playwright

from infra_assessor.storage.models import Assessment

ENV = Environment(
    loader=FileSystemLoader(Path(__file__).with_name("templates")),
    autoescape=select_autoescape(["html", "xml"]),
)
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def render_report(assessment: Assessment) -> str:
    counts = {level: 0 for level in ORDER}
    for finding in assessment.findings:
        counts[finding.severity] += 1
    by_id = {d.id: d for d in assessment.devices}
    findings = sorted(assessment.findings, key=lambda f: ORDER[f.severity])
    return ENV.get_template("report.html").render(
        assessment=assessment, counts=counts, findings=findings, by_id=by_id
    )


async def render_pdf(html: str) -> bytes:
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            page = await browser.new_page()
            await page.set_content(html, wait_until="networkidle")
            output = await page.pdf(
                format="A4",
                print_background=True,
                margin={"top": "15mm", "bottom": "15mm", "left": "12mm", "right": "12mm"},
            )
            await browser.close()
            return output
    except Exception as exc:
        raise RuntimeError(
            "PDF generation failed. Ensure Playwright Chromium is installed."
        ) from exc
