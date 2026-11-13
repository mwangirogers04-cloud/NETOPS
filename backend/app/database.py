from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


db_url = str(settings.database_url).strip()

# Normalize cloud-provided PostgreSQL connection strings (Render / Heroku / Neon use postgres:// or postgresql://)
if db_url.startswith("postgres://"):
    db_url = "postgresql+psycopg://" + db_url[len("postgres://"):]
elif db_url.startswith("postgresql://") and not db_url.startswith("postgresql+"):
    db_url = "postgresql+psycopg://" + db_url[len("postgresql://"):]

if db_url.startswith("sqlite"):
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )
else:
    # PostgreSQL with psycopg (psycopg3):
    # pool_size=20, max_overflow=20 (up to 40 connections max) with pool_timeout=30s
    # pool_pre_ping=True ensures dead connections are dropped before checkout
    # pool_recycle=300 refreshes pooled connections every 5 minutes to avoid stale cloud sockets
    engine_kwargs = {
        "pool_pre_ping": True,
        "pool_size": 20,
        "max_overflow": 20,
        "pool_recycle": 300,
        "pool_timeout": 30,
    }

    # Only pass server-side statement options if not running on external managed pooler
    if "pooler" not in db_url and "pgbouncer" not in db_url:
        engine_kwargs["connect_args"] = {
            "options": "-c idle_in_transaction_session_timeout=60000 -c statement_timeout=30000"
        }

    engine = create_engine(db_url, **engine_kwargs)


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
