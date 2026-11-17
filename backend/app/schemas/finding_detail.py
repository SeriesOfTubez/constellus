"""Documents the typed part of `GET /api/findings/{id}`.

Its own module because it needs the exposure path (planning#347), the
attribution (planning#358) and the timeline (planning#360) schemas, and the
second imports the first.
"""

from pydantic import BaseModel, ConfigDict

from app.schemas.attribution_chain import Attribution
from app.schemas.exposure_path import ExposurePath
from app.schemas.finding_timeline import TimelineEvent


class FindingDetailResponse(BaseModel):
    """The rest of that response is still an untyped dict, hence `extra="allow"`."""

    model_config = ConfigDict(extra="allow")

    exposure_paths: list[ExposurePath]
    # The attribution of the finding's own asset; None when it has no asset.
    attribution: Attribution | None
    # The dates we hold, sorted by date (planning#360).
    timeline: list[TimelineEvent]
