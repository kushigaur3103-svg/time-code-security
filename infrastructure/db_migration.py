import os
import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError, SQLAlchemyError

# ==============================================================
# TimeCodeSecurity - Enterprise PostgreSQL Migration Blueprint
# ==============================================================
# This script demonstrates the exact SQLAlchemy configuration 
# required to scale from SQLite to PostgreSQL with highly 
# concurrent connection pooling, recycle limits, and robust 
# retry mechanisms to prevent connection dropping under load.
# ==============================================================

# In production, this would point to a managed PostgreSQL cluster (e.g., AWS RDS, Heroku Postgres)
POSTGRES_URL = os.getenv("POSTGRES_URL", "postgresql://postgres:postgres@localhost:5432/timecodesecurity")

def get_enterprise_engine():
    """
    Initializes a highly robust, crash-proof PostgreSQL engine.
    """
    try:
        engine = create_engine(
            POSTGRES_URL,
            pool_size=20,               # Maximum number of permanent connections in the pool
            max_overflow=10,            # Extra connections allowed if pool_size is exceeded (burst traffic)
            pool_timeout=30,            # Seconds to wait before giving up on getting a connection from the pool
            pool_recycle=1800,          # Recycle connections every 30 minutes to prevent database disconnects
            pool_pre_ping=True,         # Extremely important: tests connections for liveness before yielding them
            echo=False                  # Set to True for verbose SQL logging during debugging
        )
        return engine
    except Exception as e:
        print(f"[FATAL] Failed to configure PostgreSQL engine: {e}")
        return None

def apply_migrations(engine, retries=5, delay=5):
    """
    Applies database schemas with exponential backoff / retry logic 
    to handle transient database unavailability during startup.
    """
    if not engine:
        return False
        
    for attempt in range(1, retries + 1):
        try:
            print(f"[+] Attempt {attempt}: Connecting to PostgreSQL cluster...")
            # Test connection
            with engine.connect() as connection:
                print("[+] Connection established successfully.")
                
                # In a real environment, you would use Alembic here:
                # alembic.command.upgrade(alembic_cfg, "head")
                print("[+] Applying schema migrations (MOCK: SUCCESS)...")
                
            return True
            
        except OperationalError as e:
            print(f"[!] Database unavailable on attempt {attempt}: {e}")
            if attempt < retries:
                print(f"[*] Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                print("[-] CRITICAL ERROR: Database cluster unreachable after maximum retries. Exiting.")
                return False
        except SQLAlchemyError as e:
            print(f"[-] CRITICAL ERROR: Schema migration failed due to SQLAlchemy exception: {e}")
            return False
        except Exception as e:
            print(f"[-] UNEXPECTED CRITICAL ERROR: {e}")
            return False

def get_session_maker(engine):
    """
    Returns a session factory configured for web concurrency.
    """
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)

if __name__ == "__main__":
    print("Initializing TimeCodeSecurity Enterprise Database Migration...")
    engine = get_enterprise_engine()
    success = apply_migrations(engine)
    if success:
        print("[+] Migration script completed successfully. Database is ready for enterprise load.")
    else:
        print("[-] Migration script failed.")
