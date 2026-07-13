from contextlib import contextmanager
from typing import Iterator

import psycopg
from psycopg.rows import dict_row

from app.config import get_settings


@contextmanager
def connection() -> Iterator[psycopg.Connection]:
    with psycopg.connect(get_settings().database_url, row_factory=dict_row) as conn:
        yield conn


def fetch_all(query: str, params: tuple = ()) -> list[dict]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(query, params)
        return list(cur.fetchall())


def fetch_one(query: str, params: tuple = ()) -> dict | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchone()


def execute(query: str, params: tuple = ()) -> None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(query, params)
