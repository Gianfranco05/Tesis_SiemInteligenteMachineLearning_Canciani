CREATE TABLE IF NOT EXISTS analistas_registrados (
    id SERIAL PRIMARY KEY,
    chat_id BIGINT UNIQUE NOT NULL,
    nombre TEXT,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alertas_fuerza_bruta (
    id SERIAL PRIMARY KEY,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    detalle TEXT
);

CREATE TABLE IF NOT EXISTS alertas_accesos_nocturnos (
    id SERIAL PRIMARY KEY,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    detalle TEXT
);

CREATE TABLE IF NOT EXISTS alertas_spikes_recursos (
    id SERIAL PRIMARY KEY,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    detalle TEXT
);

CREATE TABLE IF NOT EXISTS alertas_ml (
    id SERIAL PRIMARY KEY,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    algoritmo TEXT,
    ip_origen TEXT,
    score_riesgo FLOAT,
    accion TEXT
);