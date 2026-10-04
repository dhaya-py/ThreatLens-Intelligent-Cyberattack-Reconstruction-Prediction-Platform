from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from app.models import Base

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _alembic_config(url: str) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    return config


def _assert_round_trip(url: str) -> None:
    config = _alembic_config(url)
    command.upgrade(config, "head")

    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(conn)
            diff = compare_metadata(context, Base.metadata)
        assert diff == [], f"models and migrations have drifted: {diff}"
        assert set(Base.metadata.tables) <= set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    command.downgrade(config, "base")
    engine = create_engine(url)
    try:
        remaining = set(inspect(engine).get_table_names()) - {"alembic_version"}
        assert remaining == set()
    finally:
        engine.dispose()


def test_migrations_match_models_sqlite(tmp_path: Path) -> None:
    _assert_round_trip(f"sqlite:///{tmp_path / 'migrations.db'}")


@pytest.mark.postgres
def test_migrations_match_models_postgres(postgres_url: str) -> None:
    engine = create_engine(postgres_url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    engine.dispose()
    _assert_round_trip(postgres_url)
