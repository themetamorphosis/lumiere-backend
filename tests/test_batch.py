import uuid
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_batch_import_creates_items(client: AsyncClient, auth_headers):
    items = [
        {"title": f"Batch Movie {i}", "mediaType": "movie", "status": "pending"}
        for i in range(3)
    ]
    res = await client.post("/api/v1/watchlist/batch", json=items, headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["imported"] == 3
    assert data["skipped"] == 0


@pytest.mark.asyncio
async def test_batch_import_rejects_over_100(client: AsyncClient, auth_headers):
    items = [
        {"title": f"Overflow {i}", "mediaType": "movie", "status": "pending"}
        for i in range(101)
    ]
    res = await client.post("/api/v1/watchlist/batch", json=items, headers=auth_headers)
    assert res.status_code == 413
    assert "exceeds maximum" in res.json()["detail"]


@pytest.mark.asyncio
async def test_batch_import_skips_duplicates(client: AsyncClient, auth_headers):
    title = f"Dupe {uuid.uuid4().hex[:6]}"
    items = [
        {"title": title, "mediaType": "movie", "status": "pending"},
        {"title": title, "mediaType": "movie", "status": "watched"},
    ]
    res = await client.post("/api/v1/watchlist/batch", json=items, headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["imported"] == 1
    assert data["skipped"] == 1


@pytest.mark.asyncio
async def test_batch_import_skips_existing_items(client: AsyncClient, auth_headers):
    title = f"Existing {uuid.uuid4().hex[:6]}"
    # Create first
    await client.post("/api/v1/watchlist", json={
        "title": title, "mediaType": "movie", "status": "pending"
    }, headers=auth_headers)

    # Try to batch import the same title
    items = [
        {"title": title, "mediaType": "movie", "status": "pending"},
        {"title": f"New {uuid.uuid4().hex[:6]}", "mediaType": "movie", "status": "pending"},
    ]
    res = await client.post("/api/v1/watchlist/batch", json=items, headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["imported"] == 1
    assert data["skipped"] == 1


@pytest.mark.asyncio
async def test_batch_import_no_auth(client: AsyncClient):
    items = [{"title": "No Auth", "mediaType": "movie", "status": "pending"}]
    res = await client.post("/api/v1/watchlist/batch", json=items)
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_import_distinguishes_editions_and_returns_a_result_for_each_row(client, auth_headers):
    endpoint = "/api/v1/watchlist"
    film = {"title": "Dune", "mediaType": "movie", "status": "watched", "favorite": True}
    response = await client.post(f"{endpoint}/batch", headers=auth_headers, json=[
        {**film, "year": 1984},
        {**film, "year": 2021},
        {**film, "title": "dune", "year": 2021},
        {**film, "tmdbId": 438631, "year": 2021},
        {**film, "tmdbId": 438631, "title": "Dune: Part One", "year": 2020},
    ])
    assert response.status_code == 200
    assert response.json()["results"] == ["imported", "imported", "duplicate", "imported", "duplicate"]

    page = (await client.get(endpoint, headers=auth_headers)).json()
    assert page["total"] == 3
    linked = next(item for item in page["items"] if item["tmdbId"] == 438631)
    assert linked["year"] == 2021
    response = await client.patch(
        f"{endpoint}/{linked['id']}", headers=auth_headers, json={"title": "Dune: Part One"}
    )
    assert response.status_code == 200
    assert response.json()["title"] == "Dune: Part One"
    assert response.json()["tmdbId"] == 438631
