"""
storage.py — capa de persistencia en Supabase para el AI WAF.

Reemplaza la versión de SQLite de PromptGuard: en Vercel (serverless)
el disco no persiste entre invocaciones, así que el historial y las
stats viven en una tabla de Postgres en Supabase.

Requiere las variables de entorno:
  SUPABASE_URL
  SUPABASE_SERVICE_ROLE_KEY   (nunca la "anon key" — esta es la llave
                                que puede escribir sin pasar por RLS,
                                solo debe vivir en el backend)

El esquema de la tabla `analyses` está en sql/schema.sql — créalo una
vez en el SQL editor de tu proyecto de Supabase antes de desplegar.
"""

from __future__ import annotations

import os
from functools import lru_cache

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

TABLE = "analyses"


@lru_cache(maxsize=1)
def _client():
    """Cliente de Supabase, creado una sola vez por invocación (cacheado)."""
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError(
            "Faltan SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY en las "
            "variables de entorno. Configúralas en el proyecto de Vercel."
        )
    from supabase import create_client  # import perezoso

    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


def init_db() -> None:
    """No-op: el esquema de Supabase se crea una sola vez vía
    sql/schema.sql en el SQL editor, no en cada arranque de la app."""
    return None


def save_analysis(
    prompt: str,
    risk_score: int,
    risk_level_: str,
    blocked: bool,
    forwarded: bool,
    matches: list[dict],
    claude_text: str | None,
    claude_stub: bool | None,
    channel: str = "dashboard",
    from_number: str | None = None,
    bot_response: str | None = None,
) -> str:
    """Inserta un análisis y regresa el id (uuid) generado por Supabase."""
    row = {
        "channel": channel,
        "from_number": from_number,
        "message_text": prompt,
        "risk_score": risk_score,
        "risk_level": risk_level_,
        "blocked": blocked,
        "forwarded": forwarded,
        "matches": matches,
        "claude_text": claude_text,
        "claude_stub": claude_stub,
        "bot_response": bot_response,
    }
    result = _client().table(TABLE).insert(row).execute()
    return result.data[0]["id"] if result.data else ""


def get_history(limit: int = 20) -> list[dict]:
    result = (
        _client()
        .table(TABLE)
        .select("*")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return [_normalize_row(row) for row in result.data]


def get_stats() -> dict:
    client = _client()

    total = client.table(TABLE).select("id", count="exact").execute().count or 0
    blocked = (
        client.table(TABLE)
        .select("id", count="exact")
        .eq("blocked", True)
        .execute()
        .count
        or 0
    )
    allowed = total - blocked

    by_level = {"bajo": 0, "medio": 0, "alto": 0}
    for level in by_level:
        count = (
            client.table(TABLE)
            .select("id", count="exact")
            .eq("risk_level", level)
            .execute()
            .count
            or 0
        )
        by_level[level] = count

    return {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "by_risk_level": by_level,
    }


def _normalize_row(row: dict) -> dict:
    """Mapea los nombres de columna de Supabase al contrato que ya
    espera el frontend (igual que en la versión de SQLite)."""
    return {
        "id": row.get("id"),
        "created_at": row.get("created_at"),
        "prompt": row.get("message_text"),
        "risk_score": row.get("risk_score"),
        "risk_level": row.get("risk_level"),
        "blocked": bool(row.get("blocked")),
        "forwarded": bool(row.get("forwarded")),
        "matches": row.get("matches") or [],
        "claude_text": row.get("claude_text"),
        "claude_stub": row.get("claude_stub"),
        "channel": row.get("channel"),
        "from_number": row.get("from_number"),
    }
