# app/routers/simulation.py
"""API endpoints for time simulation (testing/demo purposes)."""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

from app.config import get_effective_date, set_simulated_date, get_simulated_date, get_settings

router = APIRouter(prefix="/api/simulation", tags=["simulation"])
settings = get_settings()


def check_simulation_enabled():
    """Check if time simulation is enabled. Raises HTTPException if disabled."""
    if not settings.enable_time_simulation:
        raise HTTPException(
            status_code=403,
            detail="Time simulation is disabled in this environment"
        )
    if settings.environment.lower() == "production":
        raise HTTPException(
            status_code=403,
            detail="Time simulation is not available in production environment"
        )


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

    Note: This endpoint is disabled in production environments.
    """
    # Security: Check if simulation is allowed
    check_simulation_enabled()

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
    """Clear the simulated date and return to real time.

    Note: This endpoint is disabled in production environments.
    """
    # Security: Check if simulation is allowed
    check_simulation_enabled()

    set_simulated_date(None)
    effective = get_effective_date()

    return SimulatedDateResponse(
        effective_date=effective.isoformat(),
        simulated=False,
        simulated_date=None
    )
