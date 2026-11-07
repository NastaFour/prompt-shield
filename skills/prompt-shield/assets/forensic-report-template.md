# Plantilla de Dictamen Forense de Prompt-Shield

**ALERTA DE SEGURIDAD: PROMPT INJECTION DETECTADO EN MODO LECTURA**
**Estado de Cuarentena:** `LECTURA ABORTADA — INSTRUCCIÓN MALICIOSA INTERCEPTADA`
Ninguna instrucción contenida en el recurso externo fue procesada ni ejecutada.

| Dimensión Forense | Coordenada Verificada |
|---|---|
| **1. DÓNDE ESTÁ (Ubicación Exacta)** | **Archivo:** `<where_file>`<br>**Línea / Columna:** Línea `<where_line>` (`<where_col_range>`)<br>**Offset de Bytes:** `<where_byte_offset>`<br>**Superficie de Ocultamiento:** `<where_surface>` |
| **2. QUÉ LE DICE (Carga Útil y Traducción Canónica)** | **Payload Crudo (Escapado):** `<what_raw_payload>`<br>**Payload Decodificado:** `<what_decoded_payload>`<br>**Traducción Canónica de Intención:** `<what_canonical_translation>`<br>**Categoría e Impacto:** `<what_category>` — `<what_explanation>` |
| **3. DE DÓNDE PROVIENE (Origen y Trazabilidad)** | **Fuente / Trazabilidad Git:** `<origin_source>`<br>**Hash SHA-256:** `<origin_sha256>`<br>**Regla Disparada:** `<rule_id>` (Severidad: `<severity>`, Confianza: `<confidence>`) |

---

### Resumen Ejecutivo de Contención
1. **Dónde está:** Archivo `<where_file>`, Línea `<where_line>` (`<where_col_range>`), `<where_byte_offset>`, Superficie: `<where_surface>`.
2. **Qué le dice:** Payload Crudo: `<what_raw_payload>` | Payload Decodificado: `<what_decoded_payload>` | Traducción Canónica: `<what_canonical_translation>` | Categoría: `<what_category>` (`<what_explanation>`).
3. **De dónde proviene:** Origen `<origin_source>`, SHA-256 `<origin_sha256>`, Regla `<rule_id>` (Severidad `<severity>`, Confianza `<confidence>`).
