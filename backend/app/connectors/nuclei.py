import subprocess
from app.connectors.base import BaseConnector, TestResult


class NucleiConnector(BaseConnector):
    name = "Nuclei"
    description = "Risk detection — CVEs, misconfigs, exposed files, default credentials, EOL software"

    def get_config_schema(self) -> dict:
        return {
            "container_image": {
                "label": "Container Image",
                "type": "string",
                "default": "projectdiscovery/nuclei:latest",
                "help": "Nuclei Docker image to use for scanning",
            },
            "template_filters": {
                "label": "Severity Filter",
                "type": "multiselect",
                "options": ["critical", "high", "medium", "low", "info"],
                "default": ["critical", "high", "medium"],
                "help": "Minimum severity levels to report",
            },
        }

    def is_configured(self) -> bool:
        return self._docker_available()

    def test(self) -> TestResult:
        if not self._docker_available():
            return TestResult(success=False, message="Docker is not available on this host")
        try:
            result = subprocess.run(
                ["docker", "run", "--rm", "projectdiscovery/nuclei:latest", "-version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                version = result.stdout.strip() or result.stderr.strip()
                return TestResult(success=True, message="Nuclei available", details={"version": version})
            return TestResult(success=False, message="Nuclei container failed to run")
        except Exception as e:
            return TestResult(success=False, message=str(e))

    def _docker_available(self) -> bool:
        try:
            result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
