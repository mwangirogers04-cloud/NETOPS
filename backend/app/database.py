from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


db_url = str(settings.database_url)
if db_url.startswith("sqlite"):
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )
else:
    # PostgreSQL with psycopg / psycopg2:
    # pool_size=10, max_overflow=10 (up to 20 connections max) with pool_timeout=30s
    # 1. idle_in_transaction_session_timeout=60000: Terminates any transaction idle > 60s
    # 2. statement_timeout=30000: Terminates any hanging query > 30s.
    engine = create_engine(
        db_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=10,
        pool_recycle=180,
        pool_timeout=30,
        connect_args={
            "options": "-c idle_in_transaction_session_timeout=60000 -c statement_timeout=30000"
        },
    )


@event.listens_for(engine, "reset")
def on_pool_reset(dbapi_connection, connection_record, reset_state=None):
    """
    Ensure every connection returned to the pool is rolled back cleanly at the DBAPI level.
    This guarantees psycopg/psycopg2 never enters an 'invalid transaction' state or holds
    uncommitted locks across pool checkouts.
    """
    if dbapi_connection is not None:
        try:
            dbapi_connection.rollback()
        except Exception:
            pass

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            if db.is_active:
                db.rollback()
        except Exception:
            pass
        db.close()
