import logging
from typing import Any

import httpx

from app.connectors.base import NotificationConnector, TestResult

log = logging.getLogger(__name__)

# Sandbox: POST https://sandbox.api.mailtrap.io/api/send/{inbox_id}
# Live:    POST https://send.api.mailtrap.io/api/send
_SANDBOX_URL = "https://sandbox.api.mailtrap.io/api/send/{inbox_id}"
_LIVE_URL = "https://send.api.mailtrap.io/api/send"


class MailtrapConnector(NotificationConnector):
    name = "Mailtrap"
    description = "Mailtrap email delivery — sandbox inbox for testing, live API for production"

    env_key_map = {
        "api_token":  "MAILTRAP_API_TOKEN",
        "inbox_id":   "MAILTRAP_INBOX_ID",
        "mode":       "MAILTRAP_MODE",
        "from_email": "MAILTRAP_FROM_EMAIL",
        "from_name":  "MAILTRAP_FROM_NAME",
    }

    def get_config_schema(self) -> dict[str, Any]:
        return {
            "api_token":  {"label": "API Token",    "type": "secret", "help": "Found in Mailtrap account settings"},
            "inbox_id":   {"label": "Inbox ID",     "type": "string", "help": "Integer inbox ID (required for sandbox — found in Mailtrap dashboard)"},
            "mode":       {"label": "Mode",         "type": "select", "options": ["sandbox", "live"], "default": "sandbox"},
            "from_email": {"label": "From address", "type": "string", "help": "Sender email address, e.g. noreply@example.com"},
            "from_name":  {"label": "From name",    "type": "string", "help": "Sender display name", "default": "Constellus"},
        }

    def is_configured(self) -> bool:
        from app.core.secrets import get_secret
        # Token alone isn't enough — inbox_id is required to actually send
        return bool(get_secret("MAILTRAP_API_TOKEN") and get_secret("MAILTRAP_INBOX_ID"))

    def _test(self, config: dict[str, Any]) -> TestResult:
        from_email = config.get("from_email") or "noreply@constellus.local"
        ok = self.send(
            subject="Constellus — email connection test",
            body_text="This is a test email from Constellus. Email delivery is working.",
            body_html="<p>This is a test email from <strong>Constellus</strong>. Email delivery is working.</p>",
            recipients=[from_email],
            config=config,
        )
        if ok:
            return TestResult(success=True, message=f"Test email sent to {from_email}")
        return TestResult(success=False, message="Failed to send — check API token and inbox ID in logs")

    def send(
        self,
        subject: str,
        body_text: str,
        recipients: list[str],
        config: dict[str, Any],
        body_html: str | None = None,
    ) -> bool:
        token = config.get("api_token", "")
        inbox_id = config.get("inbox_id", "")
        mode = config.get("mode", "sandbox")
        from_email = config.get("from_email", "noreply@constellus.local")
        from_name = config.get("from_name", "Constellus")

        if not token:
            log.error("Mailtrap: api_token not configured")
            return False

        if mode == "sandbox":
            if not inbox_id:
                log.error("Mailtrap: inbox_id is required for sandbox mode")
                return False
            url = _SANDBOX_URL.format(inbox_id=inbox_id)
        else:
            url = _LIVE_URL

        payload: dict[str, Any] = {
            "from": {"email": from_email, "name": from_name},
            "to": [{"email": addr} for addr in recipients],
            "subject": subject,
            "text": body_text,
        }
        if body_html:
            payload["html"] = body_html

        try:
            resp = httpx.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                timeout=15,
            )
            resp.raise_for_status()
            log.info("Mailtrap: email sent to %s (mode=%s)", recipients, mode)
            return True
        except httpx.HTTPStatusError as exc:
            log.error("Mailtrap HTTP error %s: %s", exc.response.status_code, exc.response.text)
        except Exception as exc:
            log.error("Mailtrap send failed: %s", exc)
        return False
