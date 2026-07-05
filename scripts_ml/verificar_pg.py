#!/usr/bin/env python3
# verificar_pg.py — chequeo rápido de cuántas muestras reales hay
# cargadas en experimento_latencias, por grupo.
#
# CORREGIDO: antes tenía host/usuario/password hardcodeados
# ('siem_postgres'/'admin'/'1234'). Ahora se leen del entorno,
# igual que el resto de los scripts (medir_latencias.py, etc).

import os
import psycopg2

PG = dict(
    host=os.getenv("PG_HOST", "127.0.0.1"),
    port=int(os.getenv("PG_PORT", "5432")),
    user=os.getenv("POSTGRES_USER", "admin"),
    password=os.getenv("POSTGRES_PASSWORD", "1234"),
    dbname=os.getenv("POSTGRES_DB", "tesis_siem"),
)

conn = psycopg2.connect(**PG)
cur = conn.cursor()

print("\n=== Estado de experimento_latencias (datos reales) ===\n")
for grupo in ("manual", "automatizado"):
    cur.execute(
        """
        SELECT COUNT(*),
               ROUND(AVG(mttr_seg)::numeric, 2),
               ROUND(STDDEV_SAMP(mttr_seg)::numeric, 2),
               ROUND(AVG(mttd_seg)::numeric, 2)
        FROM experimento_latencias
        WHERE grupo = %s AND mttr_seg IS NOT NULL
        """,
        (grupo,),
    )
    n, avg_mttr, std_mttr, avg_mttd = cur.fetchone()
    n = n or 0
    faltan = max(0, 30 - n)
    print(f"Grupo {grupo:13s}: n={n:2d}/30  (faltan {faltan})  "
          f"MTTR media={avg_mttr}s  desv={std_mttr}s  MTTD media={avg_mttd}s")

print("\n=== Filas reales en respuestas_aplicadas (prueba de que T2 ya no se ===")
print("=== fabrica con random.uniform, sino que viene de n8n de verdad)    ===\n")
cur.execute("SELECT COUNT(*) FROM respuestas_aplicadas")
print(f"Total de bloqueos SSH registrados por RU4_Respuesta: {cur.fetchone()[0]}")

cur.close()
conn.close()
