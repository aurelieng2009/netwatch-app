"""Point d'entrée : python -m app.main"""
from __future__ import annotations

import logging

import uvicorn

from .api import create_app
from .config import config
from .db import DB
from .engine import Engine


def build():
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    db = DB(config.db_path)
    engine = Engine(config, db)
    return create_app(config, db, engine)


def main() -> None:
    app = build()
    uvicorn.run(app, host=config.host, port=config.port, log_level="warning", proxy_headers=True)


if __name__ == "__main__":
    main()
