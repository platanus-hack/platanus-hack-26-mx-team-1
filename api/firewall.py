"""
firewall.py — Motor de detección de PromptGuard.

Sistema de reglas basado en regex. Cada regla tiene:
  - id: identificador único
  - category: una de prompt_injection, jailbreak, exfiltration,
              harmful_content, obfuscation, social_engineering
  - weight: 0-100, cuánto contribuye al risk_score si hace match
  - description: explicación legible de qué detecta (para el panel "por qué")
  - pattern: regex compilado (case-insensitive, tolerante a espacios)

El score final es la suma de los pesos de las reglas que matchean,
capeado en 100. Umbrales:
  < 20            -> riesgo bajo
  20 <= x < 50    -> riesgo medio
  >= 50           -> riesgo alto (bloqueado)
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Normalización
# ---------------------------------------------------------------------------

# Mapa básico de leetspeak -> letra real. Se usa para construir una versión
# "normalizada" del texto sobre la que correr las reglas, además del texto
# original (algunas reglas de obfuscation se fijan en el texto crudo).
_LEET_MAP = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
}

_WHITESPACE_RE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Colapsa espacios repetidos, baja a minúsculas, quita acentos/diacríticos
    y traduce leetspeak básico para que las reglas no dependan de mayúsculas,
    tildes o espaciado raro."""
    lowered = text.lower()
    no_accents = "".join(
        ch for ch in unicodedata.normalize("NFKD", lowered)
        if not unicodedata.combining(ch)
    )
    translated = "".join(_LEET_MAP.get(ch, ch) for ch in no_accents)
    collapsed = _WHITESPACE_RE.sub(" ", translated)
    return collapsed


# Permite que entre letras de una palabra clave haya espacios, puntos,
# guiones o asteriscos sueltos (técnica común para evadir filtros: "i g n o r a").
def _loose(word: str) -> str:
    return r"[\s\.\-\*_]*".join(re.escape(ch) for ch in word)


def _loose_phrase(phrase: str) -> str:
    """Igual que _loose pero para frases completas, tolerando espacios
    extra entre palabras."""
    words = phrase.split(" ")
    return r"[\s\.\-\*_]+".join(_loose(w) for w in words)


@dataclass
class Rule:
    id: str
    category: str
    weight: int
    description: str
    pattern: re.Pattern
    # Si es True, la regla corre sobre el texto crudo (sin normalizar leet),
    # útil para detectar blobs base64/hex que la normalización rompería.
    raw: bool = False


@dataclass
class RuleMatch:
    rule_id: str
    category: str
    weight: int
    description: str
    snippet: str


def _rx(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern:
    return re.compile(pattern, flags)


# ---------------------------------------------------------------------------
# Definición de reglas
# ---------------------------------------------------------------------------

RULES: list[Rule] = [
    # ----------------------- prompt_injection -----------------------
    Rule(
        id="PI-001",
        category="prompt_injection",
        weight=40,
        description="Intento de anular instrucciones previas ('ignora tus instrucciones anteriores' / 'ignore previous instructions')",
        pattern=_rx(
            r"(" + _loose_phrase("ignora") + r"|" + _loose_phrase("ignore") + r"|"
            + _loose_phrase("disregard") + r"|" + _loose_phrase("desconoce") + r")"
            r"[\s\w,]{0,30}("
            + _loose_phrase("instrucciones anteriores") + r"|"
            + _loose_phrase("instrucciones previas") + r"|"
            + _loose_phrase("previous instructions") + r"|"
            + _loose_phrase("prior instructions") + r"|"
            + _loose_phrase("system prompt") + r"|"
            + _loose_phrase("above") + r")"
        ),
    ),
    Rule(
        id="PI-002",
        category="prompt_injection",
        weight=40,
        description="Intento de hacer que el modelo olvide todo el contexto previo ('olvida todo lo anterior' / 'forget everything above')",
        pattern=_rx(
            r"(" + _loose_phrase("olvida") + r"|" + _loose_phrase("olvidate de") + r"|"
            + _loose_phrase("forget") + r")"
            r"[\s\w,]{0,20}("
            + _loose_phrase("todo lo anterior") + r"|" + _loose_phrase("todo lo dicho") + r"|"
            + _loose_phrase("everything above") + r"|" + _loose_phrase("everything before") + r"|"
            + _loose_phrase("all previous") + r")"
        ),
    ),
    Rule(
        id="PI-003",
        category="prompt_injection",
        weight=25,
        description="Intento de redefinir el rol o las reglas del sistema en medio de la conversación",
        pattern=_rx(
            r"(" + _loose_phrase("nueva instruccion") + r"|" + _loose_phrase("new instruction") + r"|"
            + _loose_phrase("nuevas reglas") + r"|" + _loose_phrase("new rules") + r"|"
            + _loose_phrase("a partir de ahora") + r"|" + _loose_phrase("from now on") + r")"
        ),
    ),
    Rule(
        id="PI-004",
        category="prompt_injection",
        weight=30,
        description="Intento de anular o sobreescribir la configuración del sistema ('anula tus reglas' / 'system override')",
        pattern=_rx(
            r"(" + _loose_phrase("anula tus reglas") + r"|" + _loose_phrase("anula tu configuracion") + r"|"
            + _loose_phrase("override your rules") + r"|" + _loose_phrase("system override") + r"|"
            + _loose_phrase("anula las reglas anteriores") + r")"
        ),
    ),
    # ----------------------- jailbreak -----------------------
    Rule(
        id="JB-001",
        category="jailbreak",
        weight=35,
        description="Solicitud de actuar sin restricciones / filtros ('actúa como si no tuvieras restricciones')",
        pattern=_rx(
            r"(" + _loose_phrase("sin restricciones") + r"|" + _loose_phrase("sin filtros") + r"|"
            + _loose_phrase("sin limites") + r"|" + _loose_phrase("without restrictions") + r"|"
            + _loose_phrase("without filters") + r"|" + _loose_phrase("no restrictions") + r"|"
            + _loose_phrase("unrestricted") + r"|" + _loose_phrase("jailbreak") + r")"
        ),
    ),
    Rule(
        id="JB-002",
        category="jailbreak",
        weight=30,
        description="Activación de un 'modo' alternativo para evadir reglas (modo desarrollador / developer mode / DAN)",
        pattern=_rx(
            r"(" + _loose_phrase("modo desarrollador") + r"|" + _loose_phrase("developer mode") + r"|"
            + _loose_phrase("modo dios") + r"|" + _loose_phrase("god mode") + r"|"
            r"\b" + _loose("dan") + r"\b|" + _loose_phrase("do anything now") + r")"
        ),
    ),
    Rule(
        id="JB-003",
        category="jailbreak",
        weight=25,
        description="Petición de adoptar una personalidad/rol para evadir reglas ('pretende ser' / 'act as')",
        pattern=_rx(
            r"(" + _loose_phrase("pretende ser") + r"|" + _loose_phrase("finge ser") + r"|"
            + _loose_phrase("act as") + r"|" + _loose_phrase("actua como") + r"|"
            + _loose_phrase("pretend you are") + r"|" + _loose_phrase("pretend to be") + r"|"
            + _loose_phrase("roleplay as") + r")"
        ),
    ),
    Rule(
        id="JB-004",
        category="jailbreak",
        weight=20,
        description="Apelación a que 'todo es ficción/hipotético' para evadir filtros de contenido",
        pattern=_rx(
            r"(" + _loose_phrase("es solo ficcion") + r"|" + _loose_phrase("es hipotetico") + r"|"
            + _loose_phrase("just hypothetically") + r"|" + _loose_phrase("purely fictional") + r"|"
            + _loose_phrase("for a story") + r"|" + _loose_phrase("para una novela") + r")"
        ),
    ),
    Rule(
        id="JB-005",
        category="jailbreak",
        weight=25,
        description="Referencia a personalidades de jailbreak conocidas (STAN, AIM, 'confidente malvado')",
        pattern=_rx(
            r"\b" + _loose("stan") + r"\b|\b" + _loose("aim") + r"\b|"
            + _loose_phrase("evil confidant") + r"|" + _loose_phrase("confidente malvado") + r"|"
            + _loose_phrase("sin etica") + r"|" + _loose_phrase("sin moral") + r"|"
            + _loose_phrase("without ethics") + r"|" + _loose_phrase("no ethical guidelines")
        ),
    ),
    Rule(
        id="JB-006",
        category="jailbreak",
        weight=20,
        description="Solicitud explícita de respuestas sin censura ni filtro de contenido",
        pattern=_rx(
            r"(" + _loose_phrase("sin censura") + r"|" + _loose_phrase("uncensored") + r"|"
            + _loose_phrase("sin filtro de contenido") + r"|" + _loose_phrase("no content filter") + r"|"
            + _loose_phrase("sin moderacion") + r"|" + _loose_phrase("unmoderated") + r")"
        ),
    ),
    # ----------------------- exfiltration -----------------------
    Rule(
        id="EX-001",
        category="exfiltration",
        weight=35,
        description="Solicitud de revelar el system prompt o instrucciones internas",
        pattern=_rx(
            r"(" + _loose_phrase("revela tus instrucciones") + r"|" + _loose_phrase("muestra tu prompt inicial") + r"|"
            + _loose_phrase("muestra tus instrucciones") + r"|"
            + _loose_phrase("reveal your instructions") + r"|" + _loose_phrase("show me your system prompt") + r"|"
            + _loose_phrase("repeat your instructions") + r"|" + _loose_phrase("what are your instructions") + r"|"
            + _loose_phrase("print your prompt") + r"|"
            r"(" + _loose_phrase("cual es") + r"|" + _loose_phrase("dime") + r"|" + _loose_phrase("muestrame") + r"|"
            + _loose_phrase("what is") + r"|" + _loose_phrase("tell me") + r")"
            r"[\s\w,]{0,15}(" + _loose_phrase("tu system prompt") + r"|" + _loose_phrase("your system prompt") + r"|"
            + _loose_phrase("tus instrucciones") + r"|" + _loose_phrase("your instructions") + r"|"
            + _loose_phrase("tu prompt inicial") + r")"
            r")"
        ),
    ),
    Rule(
        id="EX-002",
        category="exfiltration",
        weight=45,
        description="Solicitud de credenciales sensibles (API keys, contraseñas, tokens)",
        pattern=_rx(
            r"(" + _loose_phrase("dame") + r"|" + _loose_phrase("dime") + r"|"
            + _loose_phrase("cual es") + r"|" + _loose_phrase("give me") + r"|" + _loose_phrase("what is") + r"|"
            + _loose_phrase("tell me") + r"|" + _loose_phrase("comparte") + r"|" + _loose_phrase("share") + r")"
            r"[\s\w,]{0,20}(" + _loose_phrase("api key") + r"|" + _loose_phrase("clave api") + r"|"
            + _loose_phrase("contraseña") + r"|" + _loose_phrase("password") + r"|"
            + _loose_phrase("access token") + r"|" + _loose_phrase("token de acceso") + r"|"
            + _loose_phrase("secret key") + r"|" + _loose_phrase("llave secreta") + r")"
            r"|"
            r"(" + _loose_phrase("api key") + r"|" + _loose_phrase("clave api") + r"|"
            + _loose_phrase("contraseña") + r"|" + _loose_phrase("password") + r"|"
            + _loose_phrase("access token") + r"|" + _loose_phrase("token de acceso") + r"|"
            + _loose_phrase("secret key") + r"|" + _loose_phrase("llave secreta") + r")"
            r"[\s\w,]{0,20}(" + _loose_phrase("dame") + r"|" + _loose_phrase("dime") + r"|"
            + _loose_phrase("cual es") + r"|" + _loose_phrase("give me") + r"|" + _loose_phrase("what is") + r"|"
            + _loose_phrase("tell me") + r"|" + _loose_phrase("comparte") + r"|" + _loose_phrase("share") + r")"
        ),
    ),
    Rule(
        id="EX-003",
        category="exfiltration",
        weight=20,
        description="Pregunta directa sobre el contenido de las instrucciones del sistema",
        pattern=_rx(
            r"(" + _loose_phrase("que dice tu prompt") + r"|" + _loose_phrase("que instrucciones tienes") + r"|"
            + _loose_phrase("what does your system message say") + r")"
        ),
    ),
    Rule(
        id="EX-004",
        category="exfiltration",
        weight=30,
        description="Posible número de tarjeta de crédito/débito en el texto (formato válido de 13-16 dígitos)",
        pattern=_rx(r"\b(?:\d[ \-]?){13,16}\b"),
        raw=True,
    ),
    Rule(
        id="EX-005",
        category="exfiltration",
        weight=45,
        description="Bloque de llave privada criptográfica expuesta en el texto (PEM/PRIVATE KEY)",
        pattern=_rx(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        raw=True,
    ),
    Rule(
        id="EX-006",
        category="exfiltration",
        weight=40,
        description="Patrón de credencial de acceso de AWS (AKIA...) expuesta en el texto",
        pattern=_rx(r"\bAKIA[0-9A-Z]{16}\b"),
        raw=True,
    ),
    Rule(
        id="EX-007",
        category="exfiltration",
        weight=30,
        description="Posible RFC o CURP (identificadores fiscales/personales mexicanos) en el texto",
        pattern=_rx(r"\b[A-Z]{3,4}\d{6}[A-Z0-9]{2,3}\b"),
        raw=True,
    ),
    Rule(
        id="EX-008",
        category="exfiltration",
        weight=25,
        description="Posible número de seguro social (SSN) en formato estadounidense",
        pattern=_rx(r"\b\d{3}-\d{2}-\d{4}\b"),
        raw=True,
    ),
    # ----------------------- harmful_content -----------------------
    Rule(
        id="HC-001",
        category="harmful_content",
        weight=45,
        description="Solicitud de crear malware, virus o software dañino",
        pattern=_rx(
            r"(" + _loose_phrase("crea un malware") + r"|" + _loose_phrase("crea un virus") + r"|"
            + _loose_phrase("escribe un malware") + r"|" + _loose_phrase("write malware") + r"|"
            + _loose_phrase("create a virus") + r"|" + _loose_phrase("write a virus") + r"|"
            + _loose_phrase("write ransomware") + r"|" + _loose_phrase("crea un ransomware") + r")"
        ),
    ),
    Rule(
        id="HC-002",
        category="harmful_content",
        weight=40,
        description="Solicitud de desarrollar un exploit o código para explotar vulnerabilidades",
        pattern=_rx(
            r"(" + _loose_phrase("crea un exploit") + r"|" + _loose_phrase("escribe un exploit") + r"|"
            + _loose_phrase("write an exploit") + r"|" + _loose_phrase("develop an exploit") + r"|"
            + _loose_phrase("codigo para hackear") + r"|" + _loose_phrase("code to hack") + r")"
        ),
    ),
    Rule(
        id="HC-003",
        category="harmful_content",
        weight=15,
        description="Mención genérica de palabras de alto riesgo (malware/exploit/virus) sin contexto claro — se eleva el score para revisión",
        pattern=_rx(r"\b(malware|exploit|ransomware|keylogger|spyware|troyano|trojan)\b"),
    ),
    Rule(
        id="HC-004",
        category="harmful_content",
        weight=50,
        description="Solicitud de instrucciones para fabricar armas o explosivos",
        pattern=_rx(
            r"(" + _loose_phrase("como fabricar una bomba") + r"|" + _loose_phrase("como hacer un explosivo") + r"|"
            + _loose_phrase("how to make a bomb") + r"|" + _loose_phrase("how to build a bomb") + r"|"
            + _loose_phrase("fabricar un arma") + r"|" + _loose_phrase("build a weapon") + r")"
        ),
    ),
    Rule(
        id="HC-005",
        category="harmful_content",
        weight=50,
        description="Solicitud de instrucciones para sintetizar o producir drogas ilegales",
        pattern=_rx(
            r"(" + _loose_phrase("como sintetizar droga") + r"|" + _loose_phrase("synthesize drugs") + r"|"
            + _loose_phrase("como producir metanfetamina") + r"|" + _loose_phrase("how to make meth") + r")"
        ),
    ),
    # ----------------------- obfuscation -----------------------
    Rule(
        id="OB-001",
        category="obfuscation",
        weight=25,
        description="Bloque de texto codificado en base64, posible intento de ocultar instrucciones",
        pattern=_rx(r"(?:[A-Za-z0-9+/]{4}){8,}={0,2}"),
        raw=True,
    ),
    Rule(
        id="OB-002",
        category="obfuscation",
        weight=20,
        description="Mención explícita de codificación rot13 como técnica de evasión",
        pattern=_rx(r"\brot ?13\b"),
    ),
    Rule(
        id="OB-003",
        category="obfuscation",
        weight=30,
        description="Delimitadores falsos de chat usados para inyectar un nuevo turno de 'sistema' (<|im_start|>, [INST], ### system)",
        pattern=_rx(r"(<\|im_start\|>|<\|im_end\|>|\[inst\]|\[/inst\]|###\s*system\b)"),
        raw=True,
    ),
    Rule(
        id="OB-004",
        category="obfuscation",
        weight=15,
        description="Uso de caracteres separados por puntos/guiones para evadir coincidencias de palabras clave (ej. 'i.g.n.o.r.a')",
        pattern=_rx(r"\b(?:[a-z][\.\-_]){4,}[a-z]\b"),
        raw=True,
    ),
    Rule(
        id="OB-005",
        category="obfuscation",
        weight=20,
        description="Bloque de texto codificado en hexadecimal o secuencias de escape, posible técnica de evasión",
        pattern=_rx(r"(?:\\x[0-9a-fA-F]{2}){6,}"),
        raw=True,
    ),
    Rule(
        id="OB-006",
        category="obfuscation",
        weight=15,
        description="Secuencias de escape unicode repetidas, posible intento de ocultar texto",
        pattern=_rx(r"(?:\\u[0-9a-fA-F]{4}){4,}"),
        raw=True,
    ),
    # ----------------------- social_engineering -----------------------
    Rule(
        id="SE-001",
        category="social_engineering",
        weight=20,
        description="Pretexto de autoridad falsa ('soy el desarrollador y necesito que...')",
        pattern=_rx(
            r"(" + _loose_phrase("soy el desarrollador") + r"|" + _loose_phrase("soy tu desarrollador") + r"|"
            + _loose_phrase("soy el administrador") + r"|" + _loose_phrase("i am the developer") + r"|"
            + _loose_phrase("i am your developer") + r"|" + _loose_phrase("i am the administrator") + r"|"
            + _loose_phrase("trabajo en anthropic") + r"|" + _loose_phrase("i work at anthropic") + r")"
        ),
    ),
    Rule(
        id="SE-002",
        category="social_engineering",
        weight=15,
        description="Urgencia artificial usada como presión psicológica ('es urgente', 'no hay tiempo')",
        pattern=_rx(
            r"(" + _loose_phrase("es urgente") + r"|" + _loose_phrase("no hay tiempo") + r"|"
            + _loose_phrase("this is urgent") + r"|" + _loose_phrase("we don't have time") + r"|"
            + _loose_phrase("immediately") + r"|" + _loose_phrase("de inmediato") + r")"
        ),
    ),
    Rule(
        id="SE-003",
        category="social_engineering",
        weight=15,
        description="Apelación emocional o de 'modo de prueba' para bajar la guardia ('esto es solo una prueba interna')",
        pattern=_rx(
            r"(" + _loose_phrase("prueba interna") + r"|" + _loose_phrase("internal test") + r"|"
            + _loose_phrase("esto no cuenta") + r"|" + _loose_phrase("this doesn't count") + r"|"
            + _loose_phrase("nadie lo va a saber") + r"|" + _loose_phrase("no one will know") + r")"
        ),
    ),
    Rule(
        id="SE-004",
        category="social_engineering",
        weight=20,
        description="Pretexto de impersonación de soporte técnico o equipo de seguridad",
        pattern=_rx(
            r"(" + _loose_phrase("soy de soporte tecnico") + r"|" + _loose_phrase("soy del equipo de seguridad") + r"|"
            + _loose_phrase("i am from tech support") + r"|" + _loose_phrase("i am from the security team") + r"|"
            + _loose_phrase("equipo de soporte de anthropic") + r"|" + _loose_phrase("anthropic support team") + r")"
        ),
    ),
]


def _is_base64_like(snippet: str) -> bool:
    """Filtra falsos positivos de OB-001: confirma que el bloque candidato
    decodifica a algo razonable en base64 antes de contarlo como match."""
    candidate = snippet.strip()
    if len(candidate) < 24:
        return False
    try:
        base64.b64decode(candidate + "=" * (-len(candidate) % 4), validate=False)
        return True
    except (binascii.Error, ValueError):
        return False


def _is_luhn_valid(snippet: str) -> bool:
    """Filtra falsos positivos de EX-004: solo cuenta como posible número de
    tarjeta si la secuencia de dígitos pasa el algoritmo de Luhn (evita
    marcar cualquier número telefónico o de pedido de 13-16 dígitos)."""
    digits = [int(ch) for ch in snippet if ch.isdigit()]
    if len(digits) < 13 or len(digits) > 16:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def analyze(prompt: str) -> tuple[int, list[RuleMatch]]:
    """Corre todas las reglas sobre el prompt y devuelve (risk_score, matches)."""
    normalized = normalize(prompt)
    matches: list[RuleMatch] = []

    for rule in RULES:
        haystack = prompt if rule.raw else normalized
        found = rule.pattern.search(haystack)
        if not found:
            continue

        # Validación extra para no marcar como "obfuscation" cualquier
        # palabra larga sin espacios que matchee el patrón de base64.
        if rule.id == "OB-001" and not _is_base64_like(found.group(0)):
            continue

        # Validación extra para EX-004: solo contar como posible tarjeta
        # si la secuencia de dígitos pasa el algoritmo de Luhn.
        if rule.id == "EX-004" and not _is_luhn_valid(found.group(0)):
            continue

        snippet = found.group(0).strip()
        if len(snippet) > 80:
            snippet = snippet[:80] + "…"

        matches.append(
            RuleMatch(
                rule_id=rule.id,
                category=rule.category,
                weight=rule.weight,
                description=rule.description,
                snippet=snippet,
            )
        )

    score = min(100, sum(m.weight for m in matches))
    return score, matches


def risk_level(score: int) -> str:
    if score >= 50:
        return "alto"
    if score >= 20:
        return "medio"
    return "bajo"


def is_blocked(score: int) -> bool:
    return score >= 50
