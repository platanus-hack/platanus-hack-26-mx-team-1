"""
claude_client.py — wrapper delgado sobre la API de Anthropic.

Si no hay ANTHROPIC_API_KEY configurada en el entorno, opera en modo "stub":
no llama a ningún servicio externo y devuelve una respuesta simulada, para
poder probar el flujo completo sin gastar créditos.

El SDK de Anthropic se importa de forma perezosa (dentro de la función) para
que el resto de la app funcione aunque el paquete `anthropic` no esté
instalado en modo stub.
"""

from __future__ import annotations

import os

MODEL = "claude-haiku-4-5-20251001"


def _has_api_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def is_stub_mode() -> bool:
    return not _has_api_key()


def ask_claude(prompt: str) -> dict:
    """Envía el prompt a Claude (o devuelve un stub si no hay API key).

    Devuelve un dict: {"stub": bool, "text": str, "model": str}
    """
    if is_stub_mode():
        return {
            "stub": True,
            "model": MODEL,
            "text": (
                "[MODO STUB] No hay ANTHROPIC_API_KEY configurada, así que esta "
                "respuesta es simulada. El prompt pasó el firewall y habría sido "
                "reenviado a Claude. Configura tu API key en backend/.env para "
                "obtener una respuesta real."
            ),
        }

    try:
        import anthropic  # import perezoso
    except ImportError:
        return {
            "stub": True,
            "model": MODEL,
            "text": (
                "[MODO STUB] El paquete 'anthropic' no está instalado. "
                "Corre `pip install -r requirements.txt` para habilitar "
                "llamadas reales a la API."
            ),
        }

    client = anthropic.Anthropic()
    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )

    text_parts = [block.text for block in response.content if block.type == "text"]
    return {
        "stub": False,
        "model": MODEL,
        "text": "\n".join(text_parts),
    }
