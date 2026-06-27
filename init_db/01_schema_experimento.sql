-- ════════════════════════════════════════════════════════════════
--  01_schema_experimento.sql
--  Tablas de auditoría para medir MTTD y MTTR de forma REAL.
--  Se ejecuta una sola vez contra la base tesis_siem.
--
--  Concepto:
--    T0 = inyección del evento anómalo        (lo registra el harness)
--    T1 = detección formal de la amenaza      (lo registra el sistema)
--    T2 = aplicación de la contramedida        (lo registra n8n / el analista)
--
--    MTTD = T1 - T0   (segundos)
--    MTTR = T2 - T1   (segundos)
-- ════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS experimento_latencias (
    id           SERIAL PRIMARY KEY,
    grupo        TEXT      NOT NULL CHECK (grupo IN ('manual', 'automatizado')),
    iteracion    INTEGER   NOT NULL,
    incidente    TEXT,                         -- ej: 'fuerza_bruta', 'spike', 'nocturno'
    t0_inyeccion TIMESTAMPTZ NOT NULL,          -- momento de inyección del evento
    t1_deteccion TIMESTAMPTZ,                   -- momento de detección
    t2_respuesta TIMESTAMPTZ,                   -- momento de contramedida aplicada
    -- Las latencias se calculan automáticamente (columnas generadas):
    mttd_seg DOUBLE PRECISION
        GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (t1_deteccion - t0_inyeccion))) STORED,
    mttr_seg DOUBLE PRECISION
        GENERATED ALWAYS AS (EXTRACT(EPOCH FROM (t2_respuesta  - t1_deteccion))) STORED,
    creado_en    TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (grupo, iteracion)
);

-- Tabla donde n8n confirma que aplicó el bloqueo (provee T2 del grupo automatizado).
-- Si preferís medir T2 leyendo iptables por SSH, podés omitir esta tabla.
CREATE TABLE IF NOT EXISTS respuestas_aplicadas (
    id          SERIAL PRIMARY KEY,
    ip_origen   TEXT,
    accion      TEXT,
    aplicada_en TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_exp_grupo ON experimento_latencias (grupo);
