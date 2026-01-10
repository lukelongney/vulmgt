# app/routers/simulation.py
"""API endpoints for time simulation (testing/demo purposes)."""
from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

from app.config import get_effective_date, set_simulated_date, get_simulated_date

router = APIRouter(prefix="/api/simulation", tags=["simulation"])


class SimulatedDateRequest(BaseModel):
    date: Optional[str] = None  # ISO format: "2026-01-20" or "2026-01-20T12:00:00"


class SimulatedDateResponse(BaseModel):
    effective_date: str
    simulated: bool
    simulated_date: Optional[str] = None


@router.get("/date", response_model=SimulatedDateResponse)
async def get_current_date():
    """Get the current effective date (simulated or real)."""
    effective = get_effective_date()
    simulated = get_simulated_date()

    return SimulatedDateResponse(
        effective_date=effective.isoformat(),
        simulated=simulated is not None,
        simulated_date=simulated.isoformat() if simulated else None
    )


@router.post("/date", response_model=SimulatedDateResponse)
async def set_date(request: SimulatedDateRequest):
    """
    Set or clear the simulated date.

    - Send {"date": "2026-01-20"} to simulate that date
    - Send {"date": null} or {} to clear simulation and use real time
    """
    if request.date:
        # Parse the date string
        try:
            if "T" in request.date:
                simulated = datetime.fromisoformat(request.date)
            else:
                simulated = datetime.fromisoformat(request.date + "T12:00:00")
            set_simulated_date(simulated)
        except ValueError:
            raise ValueError(f"Invalid date format: {request.date}")
    else:
        set_simulated_date(None)

    effective = get_effective_date()
    simulated = get_simulated_date()

    return SimulatedDateResponse(
        effective_date=effective.isoformat(),
        simulated=simulated is not None,
        simulated_date=simulated.isoformat() if simulated else None
    )


@router.delete("/date", response_model=SimulatedDateResponse)
async def clear_date():
    """Clear the simulated date and return to real time."""
    set_simulated_date(None)
    effective = get_effective_date()

    return SimulatedDateResponse(
        effective_date=effective.isoformat(),
        simulated=False,
        simulated_date=None
    )
