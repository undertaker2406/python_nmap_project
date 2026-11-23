"""Quản lý engine + session SQLite (singleton)."""
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import DB_URL, DB_STORAGE_DIR
from database.models import Base
from utils.logger import get_logger

log = get_logger(__name__)


class _DBManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        DB_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False để threadpool của async scan dùng được
        self.engine = create_engine(
            DB_URL, echo=False, future=True,
            connect_args={"check_same_thread": False},
        )
        self.SessionLocal = sessionmaker(
            bind=self.engine, expire_on_commit=False, future=True,
        )

    def init_db(self):
        Base.metadata.create_all(self.engine)
        log.info("Database ready at %s", DB_URL)

    @contextmanager
    def session(self):
        s = self.SessionLocal()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            log.exception("Database transaction failed, rolled back")
            raise
        finally:
            s.close()


db_manager = _DBManager()