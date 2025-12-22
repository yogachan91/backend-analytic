import httpx
from fastapi import Request, HTTPException
from ..auth import create_service_token
from ..config import EXTERNAL_ELASTIC_BASE


async def forward_to_elastic(
    endpoint: str,
    payload: dict,
    headers: dict = None  # <--- tambahkan ini
):
    service_token = create_service_token()

    if headers is None:
        headers = {}

    # Tambahkan service token ke header
    headers["X-Service-Token"] = f"Bearer {service_token}"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{EXTERNAL_ELASTIC_BASE}{endpoint}",
                json=payload,
                headers=headers
            )
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=e.response.status_code,
            detail=e.response.json() if e.response.headers.get("content-type") == "application/json"
            else e.response.text
        )

