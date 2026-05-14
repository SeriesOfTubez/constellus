import json
import os
import subprocess
import tempfile

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

_TOKEN = os.environ.get("NUCLEI_INTERNAL_TOKEN", "")

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _require_token(request: Request) -> None:
    if not _TOKEN:
        raise HTTPException(status_code=500, detail="NUCLEI_INTERNAL_TOKEN not configured")
    if request.headers.get("X-Internal-Token", "") != _TOKEN:
        raise HTTPException(status_code=403)


class ScanRequest(BaseModel):
    targets: list[str]
    severity: str = "critical,high,medium"


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scan")
def scan(req: ScanRequest, _: None = Depends(_require_token)) -> dict:
    if not req.targets:
        return {"findings": []}

    with tempfile.TemporaryDirectory() as tmpdir:
        targets_path = f"{tmpdir}/targets.txt"
        output_path = f"{tmpdir}/results.jsonl"

        with open(targets_path, "w") as f:
            f.write("\n".join(req.targets))

        result = subprocess.run(
            [
                "nuclei",
                "-list", targets_path,
                "-severity", req.severity,
                "-output", output_path,
                "-json", "-silent",
                "-disable-update-check",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )

        if result.returncode not in (0, 1):
            raise HTTPException(
                status_code=500,
                detail=f"Nuclei exited {result.returncode}: {result.stderr[:500]}",
            )

        findings: list[dict] = []
        try:
            with open(output_path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except FileNotFoundError:
            pass

        return {"findings": findings}
