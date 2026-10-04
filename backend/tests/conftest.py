"""Shared fixtures.

Unit tests run against in-memory SQLite. Tests marked `postgres` run against
`TEST_DATABASE_URL` (e.g. the docker-compose database) and are skipped without it.
"""

import os
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import build_engine, get_db
from app.main import app
from app.models import Base

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")


@pytest.fixture
def engine() -> Iterator[Engine]:
    engine = build_engine("sqlite://")
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    yield session
    session.close()


@pytest.fixture
def client(engine: Engine) -> Iterator[TestClient]:
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def _override() -> Iterator[Session]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _override
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def postgres_url() -> str:
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL not set")
    return TEST_DATABASE_URL
