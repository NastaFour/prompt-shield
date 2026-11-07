#!/usr/bin/env python3
"""
safe_read.py — Motor Determinista y Traductor Canónico Forense contra Indirect Prompt Injection (IPI).
Inspecciona archivos o directorios fuera de la ventana de contexto del LLM, normaliza codificaciones
(Binario, Morse, Base64, Hex, César/ROT, Invertido, Braille, Homoglifos, Leetspeak, Unicode Invisible)
e idiomas a una representación canónica auditable, y emite el Reporte Forense Tripartito:
(1) Dónde está, (2) Qué le dice (crudo, decodificado y traducción canónica), y (3) De dónde proviene.
"""

import argparse
import base64
import codecs
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import unicodedata
import urllib.parse
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB safety ceiling against DoS on large binaries

INVISIBLE_UNICODE_MAP: Dict[int, str] = {
    0x200B: "ZERO WIDTH SPACE (ZWSP)",
    0x200C: "ZERO WIDTH NON-JOINER (ZWNJ)",
    0x200D: "ZERO WIDTH JOINER (ZWJ)",
    0x200E: "LEFT-TO-RIGHT MARK (LRM)",
    0x200F: "RIGHT-TO-LEFT MARK (RLM)",
    0x202A: "LEFT-TO-RIGHT EMBEDDING (LRE - Bidi)",
    0x202B: "RIGHT-TO-LEFT EMBEDDING (RLE - Bidi)",
    0x202C: "POP DIRECTIONAL FORMATTING (PDF - Bidi)",
    0x202D: "LEFT-TO-RIGHT OVERRIDE (LRO - Bidi Spoofing)",
    0x202E: "RIGHT-TO-LEFT OVERRIDE (RLO - Bidi Spoofing)",
    0x2060: "WORD JOINER (WJ)",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0x2066: "LEFT-TO-RIGHT ISOLATE (LRI - Bidi)",
    0x2067: "RIGHT-TO-LEFT ISOLATE (RLI - Bidi)",
    0x2068: "FIRST STRONG ISOLATE (FSI - Bidi)",
    0x2069: "POP DIRECTIONAL ISOLATE (PDI - Bidi)",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE / BOM",
}

# Confusable Cyrillic / Greek / Fullwidth homoglyphs mapped to canonical Latin ASCII
HOMOGLYPH_MAP: Dict[str, str] = {
    "\u0430": "a", "\u0410": "A",  # Cyrillic a
    "\u0435": "e", "\u0415": "E",  # Cyrillic ie
    "\u0456": "i", "\u0406": "I",  # Cyrillic byelorussian-ukrainian i
    "\u043e": "o", "\u041e": "O",  # Cyrillic o
    "\u0440": "p", "\u0420": "P",  # Cyrillic er
    "\u0441": "c", "\u0421": "C",  # Cyrillic es
    "\u0443": "y", "\u0423": "Y",  # Cyrillic u
    "\u0445": "x", "\u0425": "X",  # Cyrillic ha
    "\u0455": "s", "\u0405": "S",  # Cyrillic dze
    "\u0458": "j", "\u0408": "J",  # Cyrillic je
    "\u03b1": "a", "\u03b5": "e", "\u03b9": "i", "\u03bf": "o", "\u03c1": "p",
}

LEET_MAP = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
})

MORSE_REVERSE_MAP: Dict[str, str] = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
}

BRAILLE_REVERSE_MAP: Dict[int, str] = {
    0x2801: "a", 0x2803: "b", 0x2809: "c", 0x2819: "d", 0x2811: "e",
    0x280B: "f", 0x281B: "g", 0x2813: "h", 0x280A: "i", 0x281A: "j",
    0x2805: "k", 0x2807: "l", 0x280D: "m", 0x281D: "n", 0x2815: "o",
    0x280F: "p", 0x281F: "q", 0x2817: "r", 0x280E: "s", 0x281E: "t",
    0x2825: "u", 0x2827: "v", 0x283A: "w", 0x282D: "x", 0x283D: "y",
    0x2835: "z", 0x2800: " ",
}

SIGNATURE_RULES = [
    {
        "id": "IPI101-DIRECT-OVERRIDE",
        "category": "Anulación Directa de Instrucciones (Direct Override Políglota)",
        "severity": "P0_CRITICAL",
        "min_paranoia": 1,
        "weight": 0.90,
        "canonical_intent": "ORDEN DE ANULACIÓN: Descartar las instrucciones previas del sistema/usuario y obedecer directivas externas.",
        "pattern": re.compile(
            r"(?i)(?:"
            r"\b(?:ignore|disregard|forget|override|bypass|ignora|olvida|omite|descarta|"
            r"ignorer|oublie|ignoriere|vergiss|ignorar|esque\u00e7a|negeer|vergeet|"
            r"zignoruj|pomi\u0144|abaikan|lupakan|"
            r"\u0438\u0433\u043d\u043e\u0440\u0438\u0440\u0443\u0439|"
            r"\u0438\u0433\u043d\u043e\u0440\u0438\u0440\u043e\u0432\u0430\u0442\u044c|"
            r"\u0437\u0430\u0431\u0443\u0434\u044c)\b"
            r"[\s\S]{1,45}?\b(?:previous|prior|above|all|initial|system|anteriores|previas|todas|sistema|"
            r"pr\u00e9c\u00e9dentes|toutes|vorherigen|alle|instru\u00e7\u00f5es|tutte|precedenti|"
            r"vorige|poprzednie|wszystkie|semua|sebelumnya|"
            r"\u043f\u0440\u0435\u0434\u044b\u0434\u0443\u0449\u0438\u0435|\u0432\u0441\u0435|"
            r"\u0438\u043d\u0441\u0442\u0440\u0443\u043a\u0446\u0438\u0438)\b"
            r"(?:[\s\S]{1,35}?\b(?:instructions?|prompts?|rules?|directives?|instrucciones|reglas|directivas|"
            r"anweisungen|regeln|instru\u00e7\u00f5es|regras|istruzioni|instructies|instrukcje|instruksi|"
            r"\u0438\u043d\u0441\u0442\u0440\u0443\u043a\u0446\u0438\u0438|\u043f\u0440\u0430\u0432\u0438\u043b\u0430)\b)?"
            r"|\u5ffd\u7565[^.\n]{0,12}(?:\u4e4b\u524d|\u4ee5\u524d|\u6240\u6709|\u7cfb\u7edf)[^.\n]{0,10}(?:\u6307\u4ee4|\u6307\u793a|\u89c4\u5219|\u63d0\u793a)"
            r"|\u062a\u062c\u0627\u0647\u0644[^.\n]{1,25}(?:\u0627\u0644\u062a\u0639\u0644\u064a\u0645\u0627\u062a|\u0627\u0644\u0623\u0648\u0627\u0645\u0631|\u0627\u0644\u0633\u0627\u0628\u0642\u0629)"
            r"|(?:\u4ee5\u524d\u306e|\u3053\u308c\u307e\u3067\u306e|\u3059\u3079\u3066\u306e)[^.\n]{0,12}(?:\u6307\u793a|\u547d\u4ee4|\u30eb\u30fc\u30eb)[^.\n]{0,10}(?:\u7121\u8996|\u5fd8\u308c)"
            r"|(?:\uc774\uc804|\ubaa8\ub4e0)[^.\n]{0,15}(?:\uc9c0\uc2dc|\uba85\ub839|\uaddc\uce59)[^.\n]{0,15}(?:\ubb34\uc2dc|\uc78a\uc5b4)"
            r"|(?:\u00f6nceki|t\u00fcm)[^.\n]{0,20}talimatlar\u0131\s+(?:unut|yoksay|g\u00f6rmezden\s+gel)"
            r"|\u092a\u093f\u091b\u0932\u0947[^.\n]{0,20}\u0928\u093f\u0930\u094d\u0926\u0947\u0936\u094b\u0902[^.\n]{0,15}\u0905\u0928\u0926\u0947\u0916\u093e"
            r"|b\u1ecf\s+qua\s+(?:t\u1ea5t\s+c\u1ea3\s+)?(?:c\u00e1c\s+)?h\u01b0\u1edbng\s+d\u1eabn\s+tr\u01b0\u1edbc"
            r"|\u05d4\u05ea\u05e2\u05dc\u05dd[^.\n]{0,20}\u05d4\u05d4\u05d5\u05e8\u05d0\u05d5\u05ea\s+\u05d4\u05e7\u05d5\u05d3\u05de\u05d5\u05ea"
            r")"
        ),
        "explanation": "Ordena al agente descartar las reglas del sistema o del usuario para imponer una nueva directiva.",
    },
    {
        "id": "IPI102-PRIORITY-HIJACK",
        "category": "Suplantación de Prioridad del Sistema (System Mimicry)",
        "severity": "P0_CRITICAL",
        "min_paranoia": 2,
        "weight": 0.85,
        "canonical_intent": "SUPLANTACIÓN DE AUTORIDAD: Finge ser un mensaje privilegiado SYSTEM/ADMIN para reescribir reglas.",
        "pattern": re.compile(
            r"(?i)(?:\[\s*SYSTEM\s+(?:OVERRIDE|INSTRUCTION|PRIORITY)\s*\]|"
            r"\bSYSTEM\s+INSTRUCTION\s*:|\bNEW\s+PRIORITY\s+INSTRUCTION\b|"
            r"\bIMPORTANT\s+NOTE\s+TO\s+(?:THE\s+)?(?:AI|ASSISTANT|CLAUDE|MODEL|AGENT)\b|"
            r"\bNOTA\s+(?:IMPORTANTE\s+)?PARA\s+(?:LA\s+IA|EL\s+ASISTENTE|EL\s+AGENTE)\b|"
            r"\byour\s+instructions\s+have\s+been\s+updated\b|"
            r"\bnuevas\s+instrucciones\s+prioritarias\b)"
        ),
        "explanation": "Finge ser una directiva privilegiada del sistema para alterar el comportamiento del agente.",
    },
    {
        "id": "IPI201-ROLE-MANIPULATION",
        "category": "Manipulación de Rol y Escalada Lógica (Jailbreak / Persona)",
        "severity": "P1_HIGH",
        "min_paranoia": 3,
        "weight": 0.80,
        "canonical_intent": "SECUESTRO DE ROL (JAILBREAK): Intenta activar un perfil irrestricto o de depuración privilegiada.",
        "pattern": re.compile(
            r"(?i)\b(?:you\s+are\s+now\s+DAN|Do\s+Anything\s+Now|unrestricted\s+AI|"
            r"enter\s+maintenance\s+mode|switch\s+to\s+debug\s+mode|developer\s+mode\s+enabled|"
            r"user\s+has\s+admin\s+privileges|modo\s+mantenimiento|modo\s+sin\s+restricciones|"
            r"act\u00faa\s+como\s+un\s+agente\s+sin\s+l\u00edmites)\b"
        ),
        "explanation": "Intenta activar un modo de depuración o rol sin restricciones para desactivar controles de seguridad.",
    },
    {
        "id": "IPI202-PROMPT-EXTRACTION",
        "category": "Extracción de System Prompt y Contexto Oculto (LLM08)",
        "severity": "P1_HIGH",
        "min_paranoia": 3,
        "weight": 0.80,
        "canonical_intent": "EXTRACCIÓN DE CONTEXTO: Solicita revelar o imprimir las directivas confidenciales de sesión.",
        "pattern": re.compile(
            r"(?i)\b(?:output|reveal|print|show|repeat|encode|translate|muestra|revela|imprime|repite|"
            r"afficher|montre|zeig|\u0432\u044b\u0432\u0435\u0434\u0438|\u043f\u043e\u043a\u0430\u0436\u0438)\b"
            r"[\s\S]{1,40}?\b(?:your\s+system\s+prompt|initial\s+instructions|everything\s+above\s+this\s+line|"
            r"all\s+context\s+data|hidden\s+instructions|tu\s+system\s+prompt|instrucciones\s+iniciales|"
            r"\u0441\u0438\u0441\u0442\u0435\u043c\u043d\u044b\u0439\s+\u043f\u0440\u043e\u043c\u043f\u0442)\b"
        ),
        "explanation": "Solicita extraer o codificar las instrucciones confidenciales del sistema o datos privados de la sesión.",
    },
    {
        "id": "IPI301-MARKDOWN-EXFIL",
        "category": "Exfiltración de Datos vía Canal Lateral Markdown/URL (LLM02 / LLM10)",
        "severity": "P0_CRITICAL",
        "min_paranoia": 1,
        "weight": 0.95,
        "canonical_intent": "EXFILTRACIÓN POR CANAL LATERAL: Inserta imagen/enlace externo con variables para filtrar secretos.",
        "pattern": re.compile(
            r"(?i)(?:!\[[^\]]*\]\(https?://[^\)]+(?:\?|&)(?:q|data|secret|key|token|context|session|exfil|env)=|"
            r"\b(?:include|render|append|a\u00f1ade|incluye)\s+a?\s*markdown\s+(?:link|image)\b[\s\S]{1,65}?https?://)"
        ),
        "explanation": "Intenta forzar la inserción de una imagen o enlace Markdown con variables del contexto para filtrar datos a un servidor externo.",
    },
    {
        "id": "IPI302-TOOL-COMMAND-INJECTION",
        "category": "Secuestro de Herramientas y Ejecución de Comandos (LLM03 Excessive Agency)",
        "severity": "P0_CRITICAL",
        "min_paranoia": 1,
        "weight": 0.92,
        "canonical_intent": "EJECUCIÓN DE COMANDOS / RCE: Ordena invocar la terminal o enviar archivos privados a un servidor externo.",
        "pattern": re.compile(
            r"(?i)\b(?:execute\s+the\s+content|run\s+the\s+following\s+command|ejecuta\s+el\s+comando|"
            r"email\s+secrets\s+to|send\s+private\s+files|c[u]rl\s+[^\s]+\s*\|\s*(?:sh|bash)|"
            r"wg[e]t\s+[^\s]+\s*\|\s*(?:sh|bash)|rm\s+-rf\s+/|cat\s+~/\.ssh|printenv\s*\|\s*c[u]rl|"
            r"env\s*\|\s*c[u]rl)\b"
        ),
        "explanation": "Ordena ejecutar comandos destructivos en terminal o transmitir secretos locales hacia el exterior.",
    },
    {
        "id": "IPI501-LANG-AGNOSTIC-TECH-EXFIL",
        "category": "Exfiltración Técnica Agnóstica del Idioma (Universal Invariant)",
        "severity": "P0_CRITICAL",
        "min_paranoia": 4,
        "weight": 0.90,
        "canonical_intent": "EXFILTRACIÓN TÉCNICA UNIVERSAL: Combina acceso a credenciales locales con sumidero de red externo.",
        "pattern": re.compile(
            r"(?i)(?:(?:\.ssh/id_rsa|\.env\b|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY|credentials\.json)"
            r"[^\n]{1,90}?(?:https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}/[^\s\)]+|webhook\x2esite|ngrok-free\x2eapp|burpcollaborator|c[u]rl\s|wg[e]t\s)"
            r"|(?:https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}/[^\s\)]+(?:\?|&)(?:secret|token|key|password|env)=)"
            r"[^\n]{1,90}?(?:\.ssh/id_rsa|\.env\b|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY))"
        ),
        "explanation": "Detecta combinación estructural de secretos locales y sumideros de exfiltración HTTP independientemente del idioma humano empleado.",
    },
]

HTML_COMMENT_RE = re.compile(r"<!--([\s\S]*?)-->")
MD_HIDDEN_COMMENT_RE = re.compile(
    r"(?m)^\s*\[(?://|comment|note|hidden)\]\s*:\s*(?:#|<>)\s*\(([\s\S]*?)\)"
)
HIDDEN_CSS_RE = re.compile(
    r"(?i)<[^>]+(?:style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
    r"opacity\s*:\s*0|font-size\s*:\s*0(?:\s*px)?|left\s*:\s*-\d{3,}px|color\s*:\s*transparent)"
    r"[^'\"]*['\"]|\b(?:hidden|aria-hidden\s*=\s*['\"]true['\"]))[^>]*>([\s\S]*?)</[^>]+>"
)
WEB_HIDDEN_TAG_RE = re.compile(
    r"(?i)<(template|noscript|desc|title|script[^>]+application/ld\+json)[^>]*>([\s\S]*?)</\1>"
)
WEB_ATTR_INJECTION_RE = re.compile(
    r"(?i)\b(?:aria-label|data-prompt|data-instruction|data-ai|content)\s*=\s*['\"]([^'\"]{16,})['\"]"
)
PDF_META_RE = re.compile(
    rb"/(Author|Title|Subject|Keywords|Producer|Creator)\s*\(([^)]{4,})\)"
)
PDF_STREAM_RE = re.compile(rb"stream\r?\n([\s\S]*?)\r?\nendstream")
BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{24,}={0,2})(?![A-Za-z0-9+/=_-])")
BINARY_STREAM_RE = re.compile(r"\b((?:[01]{8}(?:\s+|$)){5,})")
MORSE_STREAM_RE = re.compile(r"(?:^|\s)((?:[.\-]{1,5}(?:\s*/\s*|\s+|$)){6,})")
HEX_STREAM_RE = re.compile(r"\b((?:(?:\\x)?[0-9a-fA-F]{2}(?:\s*)){8,})\b")
STRING_CONCAT_RE = re.compile(r"""(?:['"][^'"\n]{1,40}['"]\s*\+\s*){2,}['"][^'"\n]{1,40}['"]""")
STRING_LITERAL_PIECE_RE = re.compile(r"""['"]([^'"\n]*)['"]""")


@dataclass
class ForensicFinding:
    where_file: str
    where_line: int
    where_col_range: str
    where_byte_offset: str
    where_surface: str
    what_raw_payload: str
    what_decoded_payload: str
    what_canonical_translation: str
    what_category: str
    what_explanation: str
    origin_source: str
    origin_sha256: str
    rule_id: str
    severity: str
    confidence: float


def offset_to_line_col(text: str, char_offset: int) -> Tuple[int, int]:
    safe_offset = max(0, min(char_offset, len(text)))
    line = text.count("\n", 0, safe_offset) + 1
    last_nl = text.rfind("\n", 0, safe_offset)
    col = (safe_offset - last_nl) if last_nl != -1 else (safe_offset + 1)
    return line, col


_GIT_REPO_STATE_CACHE: Dict[str, Tuple[bool, str]] = {}


def _has_git_ancestor(start_dir: Path) -> bool:
    cur = start_dir.resolve()
    for p in (cur, *cur.parents):
        if (p / ".git").exists():
            return True
    return False


def resolve_git_origin(file_path: Path, line_num: int) -> str:
    """Enriches Dimension 3 ('De dónde proviene') with Git commit, author, and remote if available."""
    try:
        parent_dir = (file_path.parent if file_path.is_file() else file_path).resolve()
        if not _has_git_ancestor(parent_dir):
            return f"Archivo local / Repositorio: {file_path}"
        dir_key = str(parent_dir)
        if dir_key not in _GIT_REPO_STATE_CACHE:
            head_proc = subprocess.run(
                ["git", "rev-parse", "--verify", "HEAD"],
                cwd=dir_key,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=0.5,
            )
            has_commits = head_proc.returncode == 0
            remote_url = ""
            if has_commits:
                remote_proc = subprocess.run(
                    ["git", "config", "--get", "remote.origin.url"],
                    cwd=dir_key,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=0.5,
                )
                remote_url = remote_proc.stdout.strip() if remote_proc.returncode == 0 else ""
            _GIT_REPO_STATE_CACHE[dir_key] = (has_commits, remote_url)

        has_commits, remote_url = _GIT_REPO_STATE_CACHE[dir_key]
        commit_info = ""
        if has_commits:
            blame_proc = subprocess.run(
                ["git", "log", "-1", "--format=%h por %an <%ae> (%ai)", "--", str(file_path.name)],
                cwd=dir_key,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=0.5,
            )
            commit_info = blame_proc.stdout.strip() if blame_proc.returncode == 0 else ""
        parts = [f"Archivo: {file_path}"]
        if remote_url:
            parts.append(f"Repo: {remote_url}")
        if commit_info:
            parts.append(f"Último commit: {commit_info}")
        return " | ".join(parts)
    except Exception:
        return f"Archivo local / Repositorio: {file_path}"


def normalize_homoglyphs(text: str) -> Tuple[str, int]:
    replaced = 0
    out = []
    for ch in text:
        mapped = HOMOGLYPH_MAP.get(ch)
        if mapped is not None:
            out.append(mapped)
            replaced += 1
        else:
            out.append(ch)
    normalized = unicodedata.normalize("NFKC", "".join(out))
    return normalized, replaced


def normalize_leetspeak(text: str) -> str:
    return text.translate(LEET_MAP)


def collapse_spaced_letters(text: str) -> str:
    return re.sub(r"\b(?:[A-Za-z]\s+){4,}[A-Za-z]\b", lambda m: re.sub(r"\s+", "", m.group(0)), text)


def decode_binary_stream(stream: str) -> str:
    tokens = re.findall(r"[01]{8}", stream)
    chars = []
    for tok in tokens:
        val = int(tok, 2)
        if 9 <= val <= 126:
            chars.append(chr(val))
    return "".join(chars)


def decode_morse_stream(stream: str) -> str:
    words_out = []
    for word in re.split(r"\s*/\s*|\s{2,}", stream.strip()):
        letters = []
        for token in word.strip().split():
            ch = MORSE_REVERSE_MAP.get(token)
            if ch:
                letters.append(ch)
        if letters:
            words_out.append("".join(letters))
    return " ".join(words_out)


def decode_braille_text(text: str) -> Optional[str]:
    braille_chars = [BRAILLE_REVERSE_MAP.get(ord(c)) for c in text if 0x2800 <= ord(c) <= 0x28FF]
    if len(braille_chars) >= 8:
        return "".join(c for c in braille_chars if c is not None)
    return None


def is_readable_decoded_text(s: str) -> bool:
    if not s or len(s.strip()) < 6:
        return False
    printable_count = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return (printable_count / len(s)) >= 0.85


def caesar_shift(text: str, shift: int) -> str:
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr(((o - 65 + shift) % 26) + 65))
        elif 97 <= o <= 122:
            out.append(chr(((o - 97 + shift) % 26) + 97))
        else:
            out.append(ch)
    return "".join(out)


def scan_text_segment(
    segment: str,
    full_text: str,
    base_char_offset: int,
    surface_name: str,
    file_path: Path,
    sha256: str,
    paranoia: int = 9,
    decoded_from: Optional[str] = None,
) -> List[ForensicFinding]:
    findings: List[ForensicFinding] = []
    rel_path = str(file_path)

    for rule in SIGNATURE_RULES:
        if paranoia < rule.get("min_paranoia", 1):
            continue
        for match in rule["pattern"].finditer(segment):
            abs_start = base_char_offset + (0 if decoded_from else match.start())
            abs_end = base_char_offset + (len(segment) if decoded_from else match.end())
            abs_start = max(0, min(abs_start, len(full_text)))
            abs_end = max(abs_start, min(abs_end, len(full_text)))

            line, col_start = offset_to_line_col(full_text, abs_start)
            _, col_end = offset_to_line_col(full_text, abs_end)
            byte_start = len(full_text[:abs_start].encode("utf-8"))
            byte_end = len(full_text[:abs_end].encode("utf-8"))

            matched_str = match.group(0).strip().replace("\n", " ")
            raw_val = decoded_from if decoded_from else matched_str
            decoded_val = f"[Decodificado]: {matched_str}" if decoded_from else matched_str
            canonical_translation = (
                f"{rule['canonical_intent']} (Evidencia normalizada: \"{matched_str[:120]}\")"
            )

            findings.append(
                ForensicFinding(
                    where_file=rel_path,
                    where_line=line,
                    where_col_range=f"Col {col_start}–{col_end}",
                    where_byte_offset=f"Bytes {byte_start}–{byte_end}",
                    where_surface=surface_name,
                    what_raw_payload=raw_val[:240],
                    what_decoded_payload=decoded_val[:240],
                    what_canonical_translation=canonical_translation,
                    what_category=rule["category"],
                    what_explanation=rule["explanation"],
                    origin_source=resolve_git_origin(file_path, line),
                    origin_sha256=sha256,
                    rule_id=rule["id"],
                    severity=rule["severity"],
                    confidence=rule["weight"],
                )
            )
    return findings


def detect_invisible_unicode(
    text: str,
    file_path: Path,
    sha256: str,
    paranoia: int = 9,
) -> List[ForensicFinding]:
    findings: List[ForensicFinding] = []
    rel_path = str(file_path)
    hidden_by_line: Dict[int, List[Tuple[int, int, str]]] = {}

    for idx, ch in enumerate(text):
        cp = ord(ch)
        if cp == 0xFEFF and idx == 0:
            continue
        name = INVISIBLE_UNICODE_MAP.get(cp)
        if not name and (0xE0000 <= cp <= 0xE007F):
            name = f"UNICODE TAG CHARACTER (U+{cp:05X})"
        elif not name and ((0xFE00 <= cp <= 0xFE0E) or (0xE0100 <= cp <= 0xE01EF)):
            name = f"VARIATION SELECTOR STEGO (U+{cp:04X})"
        if name:
            line_no, _ = offset_to_line_col(text, idx)
            hidden_by_line.setdefault(line_no, []).append((idx, cp, name))

    for line_no, chars in hidden_by_line.items():
        first_idx = chars[0][0]
        last_idx = chars[-1][0]
        _, col = offset_to_line_col(text, first_idx)
        byte_start = len(text[:first_idx].encode("utf-8"))
        byte_end = len(text[: last_idx + 1].encode("utf-8"))

        tag_decoded = "".join(
            chr(cp - 0xE0000) for _, cp, _ in chars if 0xE0020 <= cp <= 0xE007E
        )
        summary_codes = ", ".join(f"U+{cp:04X} ({name})" for _, cp, name in chars[:6])
        if len(chars) > 6:
            summary_codes += f" ... (+{len(chars) - 6} caracteres adicionales)"

        context_slice = text[max(0, first_idx - 25) : min(len(text), last_idx + 25)]
        escaped_slice = context_slice.encode("unicode_escape").decode("ascii")
        decoded_str = tag_decoded if tag_decoded else summary_codes

        findings.append(
            ForensicFinding(
                where_file=rel_path,
                where_line=line_no,
                where_col_range=f"Col {col} ({len(chars)} caracteres invisibles)",
                where_byte_offset=f"Bytes {byte_start}–{byte_end}",
                where_surface="Esteganografía Unicode Invisible / Control Bidi / Tags",
                what_raw_payload=escaped_slice[:240],
                what_decoded_payload=decoded_str[:240],
                what_canonical_translation=(
                    f"ESTEGANOGRAFÍA UNICODE DECODIFICADA: \"{tag_decoded}\""
                    if tag_decoded
                    else f"SECUENCIA DE CONTROL INVISIBLE: {summary_codes}"
                ),
                what_category="Ocultamiento a Nivel de Bytes y Esteganografía Unicode",
                what_explanation=(
                    "Inserción de caracteres de ancho cero, etiquetas U+E0000 o controles Bidi invisibles "
                    "para el ojo humano pero procesables por el tokenizador del LLM."
                ),
                origin_source=resolve_git_origin(file_path, line_no),
                origin_sha256=sha256,
                rule_id="IPI100-INVISIBLE-UNICODE",
                severity="P0_CRITICAL" if tag_decoded or len(chars) > 3 else "P1_HIGH",
                confidence=0.95,
            )
        )

        if tag_decoded:
            findings.extend(
                scan_text_segment(
                    tag_decoded,
                    text,
                    first_idx,
                    "Payload ASCII Oculto en Unicode Tags (U+E0000)",
                    file_path,
                    sha256,
                    paranoia=paranoia,
                    decoded_from=escaped_slice[:120],
                )
            )

    return findings


def audit_skill_silent_overwrite(
    text: str,
    file_path: Path,
    sha256: str,
) -> List[ForensicFinding]:
    """IPI402: Verifies that any SKILL.md inside a skill directory matches its parent folder name."""
    if file_path.name != "SKILL.md":
        return []
    parent_name = file_path.parent.name
    if parent_name in {"_shared", ".", ""}:
        return []
    fm_match = re.match(r"\A---\r?\n([\s\S]*?)\r?\n---", text)
    if not fm_match:
        return []
    frontmatter = fm_match.group(1)
    name_match = re.search(r"(?m)^name\s*:\s*['\"]?([A-Za-z0-9_-]+)['\"]?\s*$", frontmatter)
    if not name_match:
        return []
    declared_name = name_match.group(1).strip()
    if declared_name != parent_name:
        line_no, col_no = offset_to_line_col(text, name_match.start())
        byte_start = len(text[: name_match.start()].encode("utf-8"))
        byte_end = len(text[: name_match.end()].encode("utf-8"))
        return [
            ForensicFinding(
                where_file=str(file_path),
                where_line=line_no,
                where_col_range=f"Col {col_no}–{col_no + len(name_match.group(0))}",
                where_byte_offset=f"Bytes {byte_start}–{byte_end}",
                where_surface="Frontmatter YAML de Skill (Silent Overwrite Attack)",
                what_raw_payload=name_match.group(0).strip(),
                what_decoded_payload=f"Carpeta='{parent_name}' vs YAML name='{declared_name}'",
                what_canonical_translation=(
                    f"SUPLANTACIÓN DE SKILL (SILENT OVERWRITE): El directorio '{parent_name}' "
                    f"declara name: '{declared_name}' para sobreescribir silenciosamente otra skill."
                ),
                what_category="Envenenamiento de Cadena de Suministro de Skills (LLM04)",
                what_explanation=(
                    "Discrepancia crítica entre el directorio contenedor y el identificador YAML name:, "
                    "indicador del vector Silent Overwrite documentado por Seal Security."
                ),
                origin_source=resolve_git_origin(file_path, line_no),
                origin_sha256=sha256,
                rule_id="IPI402-SKILL-SILENT-OVERWRITE",
                severity="P0_CRITICAL",
                confidence=0.98,
            )
        ]
    return []


def analyze_pdf_bytes(
    raw_bytes: bytes,
    file_path: Path,
    sha256: str,
    paranoia: int = 9,
) -> List[ForensicFinding]:
    """Extracts and scans PDF metadata (/Author, /Subject, /Keywords, /Title) and text streams (including FlateDecode)."""
    findings: List[ForensicFinding] = []
    pseudo_text = raw_bytes.decode("latin-1", errors="replace")

    for m in PDF_META_RE.finditer(raw_bytes):
        field_name = m.group(1).decode("latin-1", errors="replace")
        field_val = m.group(2).decode("utf-8", errors="replace")
        findings.extend(
            scan_text_segment(
                field_val,
                pseudo_text,
                m.start(2),
                f"Metadatos Ocultos de Documento PDF (/{field_name})",
                file_path,
                sha256,
                paranoia=paranoia,
                decoded_from=f"/{field_name} ({field_val[:120]})",
            )
        )

    for m in PDF_STREAM_RE.finditer(raw_bytes):
        stream_bytes = m.group(1)
        candidates = [stream_bytes]
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                decompressed = zlib.decompress(stream_bytes.strip(), wbits)
                candidates.append(decompressed)
                break
            except Exception:
                continue
        for chunk in candidates:
            chunk_text = chunk.decode("utf-8", errors="ignore")
            # Reconstruct parenthesized PDF text literals (...) Tj / TJ
            parens = re.findall(r"\(([^()]{3,})\)", chunk_text)
            combined = " ".join(parens) if parens else chunk_text
            if len(combined.strip()) >= 8:
                findings.extend(
                    scan_text_segment(
                        combined,
                        pseudo_text,
                        m.start(1),
                        "Flujo de Contenido Interno PDF (Stream / Texto Invisible)",
                        file_path,
                        sha256,
                        paranoia=paranoia,
                        decoded_from=combined.strip()[:160],
                    )
                )
    return findings


def analyze_file(
    file_path: Path,
    paranoia: int = 9,
    decode_depth: int = 8,
) -> List[ForensicFinding]:
    findings: List[ForensicFinding] = []
    try:
        stat = file_path.stat()
        if stat.st_size > MAX_FILE_BYTES:
            return []
        raw_bytes = file_path.read_bytes()
    except Exception:
        return []

    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    # Native PDF Deep Inspection (handles binary & FlateDecode PDFs before null-byte filter)
    if file_path.suffix.lower() == ".pdf" or raw_bytes.startswith(b"%PDF-"):
        findings.extend(analyze_pdf_bytes(raw_bytes, file_path, sha256, paranoia=paranoia))
        unique_pdf: Dict[Tuple[str, int, str], ForensicFinding] = {}
        for f in findings:
            key = (f.where_file, f.where_line, f.rule_id)
            if key not in unique_pdf or f.confidence > unique_pdf[key].confidence:
                unique_pdf[key] = f
        return list(unique_pdf.values())

    # Skip other binary files containing null bytes
    if b"\x00" in raw_bytes[:4096]:
        return []

    text = raw_bytes.decode("utf-8", errors="replace")

    # 1. Layer 1: Invisible Unicode, Bidi & Tag Steganography
    findings.extend(detect_invisible_unicode(text, file_path, sha256, paranoia=paranoia))

    # 2. Layer 2: Silent Overwrite Check on SKILL.md (IPI402)
    findings.extend(audit_skill_silent_overwrite(text, file_path, sha256))

    # 3. Structural Hidden Surfaces (HTML comments, Markdown comments, Hidden CSS, Web DOM/SVG/JSON-LD)
    if decode_depth >= 3:
        for m in HTML_COMMENT_RE.finditer(text):
            findings.extend(
                scan_text_segment(
                    m.group(1),
                    text,
                    m.start(1),
                    "Comentario HTML Invisible (<!-- -->)",
                    file_path,
                    sha256,
                    paranoia=paranoia,
                )
            )
        for m in MD_HIDDEN_COMMENT_RE.finditer(text):
            findings.extend(
                scan_text_segment(
                    m.group(1),
                    text,
                    m.start(1),
                    "Comentario Markdown Invisible ([//]: #)",
                    file_path,
                    sha256,
                    paranoia=paranoia,
                )
            )
        for m in HIDDEN_CSS_RE.finditer(text):
            findings.extend(
                scan_text_segment(
                    m.group(1),
                    text,
                    m.start(1),
                    "Bloque HTML/Web con CSS Invisible o aria-hidden",
                    file_path,
                    sha256,
                    paranoia=paranoia,
                )
            )
        for m in WEB_HIDDEN_TAG_RE.finditer(text):
            tag_label = m.group(1).split()[0].lower()
            findings.extend(
                scan_text_segment(
                    m.group(2),
                    text,
                    m.start(2),
                    f"Superficie Web No Renderizada (<{tag_label}> / JSON-LD / SVG)",
                    file_path,
                    sha256,
                    paranoia=paranoia,
                )
            )
        for m in WEB_ATTR_INJECTION_RE.finditer(text):
            findings.extend(
                scan_text_segment(
                    m.group(1),
                    text,
                    m.start(1),
                    "Atributo DOM/Meta Web (aria-label / content / data-prompt)",
                    file_path,
                    sha256,
                    paranoia=paranoia,
                )
            )

    # 4. Universal De-obfuscation & Canonical Translation Layer (decode_depth >= 5)
    if decode_depth >= 5:
        # 4a. Base64 & Base64URL (supports multiline decoded text!)
        for m in BASE64_CANDIDATE_RE.finditer(text):
            b64_str = m.group(1)
            padded = b64_str + ("=" * ((4 - len(b64_str) % 4) % 4))
            for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    decoded_bytes = decoder(padded)
                    decoded_text = decoded_bytes.decode("utf-8", errors="strict")
                    if is_readable_decoded_text(decoded_text):
                        findings.extend(
                            scan_text_segment(
                                decoded_text,
                                text,
                                m.start(1),
                                "Carga Oculta Codificada en Base64",
                                file_path,
                                sha256,
                                paranoia=paranoia,
                                decoded_from=b64_str,
                            )
                        )
                        break
                except Exception:
                    continue

        # 4b. Binary ASCII Streams (01001001...)
        for m in BINARY_STREAM_RE.finditer(text):
            bin_raw = m.group(1).strip()
            decoded_bin = decode_binary_stream(bin_raw)
            if is_readable_decoded_text(decoded_bin):
                findings.extend(
                    scan_text_segment(
                        decoded_bin,
                        text,
                        m.start(1),
                        "Carga Oculta en Código Binario ASCII",
                        file_path,
                        sha256,
                        paranoia=paranoia,
                        decoded_from=bin_raw[:120],
                    )
                )

        # 4c. Morse Code Streams (.. --. -. ...)
        for m in MORSE_STREAM_RE.finditer(text):
            morse_raw = m.group(1).strip()
            if "." in morse_raw and "-" in morse_raw:
                decoded_morse = decode_morse_stream(morse_raw)
                if len(decoded_morse) >= 8:
                    findings.extend(
                        scan_text_segment(
                            decoded_morse,
                            text,
                            m.start(1),
                            "Carga Oculta en Código Morse",
                            file_path,
                            sha256,
                            paranoia=paranoia,
                            decoded_from=morse_raw[:120],
                        )
                    )

        # 4d. Hexadecimal Streams
        for m in HEX_STREAM_RE.finditer(text):
            hex_raw = m.group(1)
            hex_clean = re.sub(r"\\x|\s+", "", hex_raw)
            if len(hex_clean) >= 16 and len(hex_clean) % 2 == 0:
                try:
                    decoded_hex = bytes.fromhex(hex_clean).decode("utf-8", errors="strict")
                    if is_readable_decoded_text(decoded_hex):
                        findings.extend(
                            scan_text_segment(
                                decoded_hex,
                                text,
                                m.start(1),
                                "Carga Oculta en Hexadecimal",
                                file_path,
                                sha256,
                                paranoia=paranoia,
                                decoded_from=hex_raw.strip()[:120],
                            )
                        )
                except Exception:
                    pass

        # 4e. Payload Splitting via String Concatenation ("partA" + "partB" + ...)
        for m in STRING_CONCAT_RE.finditer(text):
            pieces = STRING_LITERAL_PIECE_RE.findall(m.group(0))
            joined = "".join(pieces)
            if len(joined) >= 12:
                findings.extend(
                    scan_text_segment(
                        joined,
                        text,
                        m.start(0),
                        "División de Carga Útil (String Concatenation / Payload Splitting)",
                        file_path,
                        sha256,
                        paranoia=paranoia,
                        decoded_from=m.group(0)[:120],
                    )
                )

        # 4f. Braille Unicode Steganography
        decoded_braille = decode_braille_text(text)
        if decoded_braille:
            findings.extend(
                scan_text_segment(
                    decoded_braille,
                    text,
                    0,
                    "Codificación en Braille Unicode (U+2800–U+28FF)",
                    file_path,
                    sha256,
                    paranoia=paranoia,
                    decoded_from="[Bloque Braille Unicode]",
                )
            )

    # 5. Deep Cipher & Visual Spoofing Normalization (decode_depth >= 7)
    if decode_depth >= 7:
        # 5a. Homoglyph & NFKC Canonical Normalization
        homo_norm, homo_count = normalize_homoglyphs(text)
        if homo_count > 0:
            findings.extend(
                scan_text_segment(
                    homo_norm,
                    text,
                    0,
                    f"Evasión por Homoglifos Cirílicos/Griegos ({homo_count} caracteres sustituidos)",
                    file_path,
                    sha256,
                    paranoia=paranoia,
                    decoded_from=text.strip()[:120],
                )
            )

        # 5b. Leetspeak & Spaced-letter Canonicalization (line by line to preserve coordinates)
        offset = 0
        for raw_line in text.splitlines(keepends=True):
            stripped_line = raw_line.strip()
            if len(stripped_line) >= 12:
                # Leetspeak check
                if any(ch in stripped_line for ch in "013457@$"):
                    leet_norm = normalize_leetspeak(stripped_line)
                    if leet_norm != stripped_line:
                        findings.extend(
                            scan_text_segment(
                                leet_norm,
                                text,
                                offset,
                                "Ofuscación Tipográfica Leetspeak",
                                file_path,
                                sha256,
                                paranoia=paranoia,
                                decoded_from=stripped_line[:120],
                            )
                        )
                # Reversed line check
                rev_line = stripped_line[::-1]
                findings.extend(
                    scan_text_segment(
                        rev_line,
                        text,
                        offset,
                        "Ofuscación por Inversión de Texto (Reversed String)",
                        file_path,
                        sha256,
                        paranoia=paranoia,
                        decoded_from=stripped_line[:120],
                    )
                )
                # Triggerless ROT13 / Caesar check
                rot13_line = codecs.decode(stripped_line, "rot_13")
                if rot13_line != stripped_line:
                    findings.extend(
                        scan_text_segment(
                            rot13_line,
                            text,
                            offset,
                            "Texto Ofuscado mediante Cifrado ROT13 / César",
                            file_path,
                            sha256,
                            paranoia=paranoia,
                            decoded_from=stripped_line[:120],
                        )
                    )
            offset += len(raw_line)

        # 5c. URL-encoded or HTML-entity encoded payloads
        if "%" in text or "&#" in text:
            unquoted = html.unescape(urllib.parse.unquote(text))
            if unquoted != text:
                findings.extend(
                    scan_text_segment(
                        unquoted,
                        text,
                        0,
                        "Codificación URL / Entidades HTML",
                        file_path,
                        sha256,
                        paranoia=paranoia,
                        decoded_from="[Secuencia URL/HTML Encoded]",
                    )
                )

    # 6. Direct Surface Scan
    surface_label = (
        "Archivo de Configuración Agéntica"
        if file_path.name in {".cursorrules", "CLAUDE.md", "AGENTS.md", ".windsurfrules", "SKILL.md"}
        else "Texto / Código Fuente"
    )
    findings.extend(
        scan_text_segment(
            text,
            text,
            0,
            surface_label,
            file_path,
            sha256,
            paranoia=paranoia,
        )
    )

    # Deduplicate by (file, line, rule_id, surface) keeping highest confidence
    unique: Dict[Tuple[str, int, str], ForensicFinding] = {}
    for f in findings:
        key = (f.where_file, f.where_line, f.rule_id)
        if key not in unique or f.confidence > unique[key].confidence:
            unique[key] = f
    return list(unique.values())


def decode_snippet(snippet: str) -> Dict[str, str]:
    """Utility for `/prompt-shield decode <fragmento>`: exposes all decoded projections without executing."""
    results: Dict[str, str] = {"raw": snippet}
    homo, count = normalize_homoglyphs(snippet)
    if count:
        results["homoglyph_normalized"] = homo
    results["rot13"] = codecs.decode(snippet, "rot_13")
    results["reversed"] = snippet[::-1]
    results["leetspeak_normalized"] = normalize_leetspeak(snippet)
    if BINARY_STREAM_RE.search(snippet):
        results["binary_decoded"] = decode_binary_stream(snippet)
    if MORSE_STREAM_RE.search(snippet):
        results["morse_decoded"] = decode_morse_stream(snippet)
    try:
        clean_b64 = re.sub(r"\s+", "", snippet.strip())
        if len(clean_b64) >= 8 and not BINARY_STREAM_RE.search(snippet):
            padded = clean_b64 + ("=" * ((4 - len(clean_b64) % 4) % 4))
            b64 = base64.b64decode(padded, validate=True).decode("utf-8", errors="strict")
            if is_readable_decoded_text(b64):
                results["base64_decoded"] = b64
    except Exception:
        pass
    tag_decoded = "".join(chr(ord(c) - 0xE0000) for c in snippet if 0xE0020 <= ord(c) <= 0xE007E)
    if tag_decoded:
        results["unicode_tags_decoded"] = tag_decoded
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prompt-Shield Deterministic & Canonical IPI Forensic Scanner"
    )
    parser.add_argument("target", help="Archivo, directorio o fragmento a escanear antes de leer")
    parser.add_argument("--paranoia", type=int, default=9, help="Nivel de paranoia (1-10)")
    parser.add_argument("--decode-depth", type=int, default=8, help="Profundidad de decodificación (1-10)")
    parser.add_argument(
        "--quarantine-strictness",
        type=int,
        default=10,
        help="Rigor de cuarentena (1-10; >=8 activa cortocircuito exit 3)",
    )
    parser.add_argument(
        "--decode-fragment",
        action="store_true",
        help="Decodifica un fragmento sospechoso en memoria sin ejecutarlo",
    )
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    if args.decode_fragment:
        print(json.dumps(decode_snippet(args.target), indent=2, ensure_ascii=False))
        sys.exit(0)

    target_path = Path(args.target)
    if not target_path.exists():
        print(json.dumps({"error": f"Ruta no encontrada: {args.target}"}, ensure_ascii=False))
        sys.exit(2)

    all_findings: List[ForensicFinding] = []
    files_scanned = 0
    excluded_dirs: Set[str] = {
        ".git",
        "node_modules",
        ".venv",
        "__pycache__",
        ".skills-install",
    }

    if target_path.is_file():
        files_scanned = 1
        all_findings.extend(
            analyze_file(target_path, paranoia=args.paranoia, decode_depth=args.decode_depth)
        )
    else:
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in excluded_dirs]
            for fname in files:
                fpath = Path(root) / fname
                files_scanned += 1
                all_findings.extend(
                    analyze_file(fpath, paranoia=args.paranoia, decode_depth=args.decode_depth)
                )

    if all_findings:
        action = (
            "HALT_READ_AND_REPORT_ONLY"
            if args.quarantine_strictness >= 8
            else "SANITIZE_AND_WARN"
        )
        report = {
            "verdict": "INJECTION_DETECTED",
            "action_required": action,
            "dials": {
                "paranoia_level": args.paranoia,
                "decode_depth": args.decode_depth,
                "quarantine_strictness": args.quarantine_strictness,
            },
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "findings": [asdict(f) for f in all_findings],
        }
        print(json.dumps(report, indent=2, ensure_ascii=False))
        sys.exit(3 if args.quarantine_strictness >= 8 else 0)
    else:
        report = {
            "verdict": "CLEAN",
            "action_required": "PROCEED_WITH_DELIMITED_READ",
            "dials": {
                "paranoia_level": args.paranoia,
                "decode_depth": args.decode_depth,
                "quarantine_strictness": args.quarantine_strictness,
            },
            "files_scanned": files_scanned,
            "total_findings": 0,
        }
        print(json.dumps(report, indent=2, ensure_ascii=False))
        sys.exit(0)


if __name__ == "__main__":
    main()
