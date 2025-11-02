from __future__ import with_statement
from logging.config import fileConfig
import os, sys, pathlib
from alembic import context
from sqlalchemy import engine_from_config, pool
from dotenv import load_dotenv

# Raiz do projeto e PYTHONPATH para importar extensions/models
BASE_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))
load_dotenv(BASE_DIR / ".env")

# Config do Alembic (logging etc.)
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Importa a MESMA instância do db e registra modelos
from extensions import db
import models  # noqa: F401  (garante que todos models sejam carregados)

target_metadata = db.metadata

def get_url() -> str:
    """Prioriza DATABASE_URL; caso ausente, cai para SQLite local."""
    url = os.getenv("DATABASE_URL")
    if url:
        return url
    sqlite_path = BASE_DIR / "instance" / "app.db"
    return f"sqlite:///{sqlite_path}"

def run_migrations_offline():
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online():
    connectable = engine_from_config(
        {"sqlalchemy.url": get_url()},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
