"""
storage.py — capa de persistencia en Supabase para el AI WAF.

Reemplaza la versión de SQLite de PromptGuard: en Vercel (serverless)
el disco no persiste entre invocaciones, así que el historial y las
stats viven en una tabla de Postgres en Supabase.

Hablamos con Supabase a través de su REST API (PostgREST) usando
`requests` directamente, en vez del cliente oficial `supabase-py`. ¿Por
qué? Porque las versiones viejas de `supabase-py` validan localmente que
la key tenga formato JWT (`eyJ...`) y rechazan con "Invalid API key" las
NUEVAS keys de Supabase (`sb_secret_...`), que ya no son JWT. Llamar a
PostgREST directo acepta CUALQUIER formato de key (la pasa tal cual en
los headers) y de paso elimina una dependencia pesada del bundle.

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

import requests

TABLE = "analyses"


def _env(name: str) -> str | None:
    """Lee una variable de entorno limpiando espacios y comillas que se
    cuelan al pegar valores en el dashboard de Vercel."""
    value = os.environ.get(name)
    if value is None:
        return None
    return value.strip().strip('"').strip("'").strip()


def _config() -> tuple[str, str]:
    url = _env("SUPABASE_URL")
    key = _env("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not key:
        raise RuntimeError(
            "Faltan SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY en las "
            "variables de entorno. Configúralas en el proyecto de Vercel."
        )
    return url.rstrip("/"), key


def _headers(key: str, extra: dict | None = None) -> dict:
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    if extra:
        headers.update(extra)
    return headers


def _rest_url(url: str) -> str:
    return f"{url}/rest/v1/{TABLE}"


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
    url, key = _config()
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
    resp = requests.post(
        _rest_url(url),
        headers=_headers(key, {"Prefer": "return=representation"}),
        json=row,
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    return data[0]["id"] if data else ""


def get_history(limit: int = 20) -> list[dict]:
    url, key = _config()
    resp = requests.get(
        _rest_url(url),
        headers=_headers(key),
        params={"select": "*", "order": "created_at.desc", "limit": limit},
        timeout=10,
    )
    resp.raise_for_status()
    return [_normalize_row(row) for row in resp.json()]


def _count(url: str, key: str, filters: dict | None = None) -> int:
    """Cuenta filas usando el header Content-Range de PostgREST sin
    transferir las filas (pide solo el rango 0-0)."""
    params = {"select": "id"}
    if filters:
        params.update(filters)
    resp = requests.get(
        _rest_url(url),
        headers=_headers(key, {"Prefer": "count=exact", "Range": "0-0"}),
        params=params,
        timeout=10,
    )
    resp.raise_for_status()
    # Content-Range viene como "0-0/137" (o "*/0" si no hay filas).
    content_range = resp.headers.get("Content-Range", "")
    total = content_range.split("/")[-1] if "/" in content_range else ""
    try:
        return int(total)
    except ValueError:
        return 0


def get_stats() -> dict:
    url, key = _config()

    total = _count(url, key)
    blocked = _count(url, key, {"blocked": "eq.true"})
    allowed = total - blocked

    by_level = {"bajo": 0, "medio": 0, "alto": 0}
    for level in by_level:
        by_level[level] = _count(url, key, {"risk_level": f"eq.{level}"})

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
