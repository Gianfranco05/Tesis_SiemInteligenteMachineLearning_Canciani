import psycopg2

conn = psycopg2.connect(host='siem_postgres', user='admin', password='1234', dbname='tesis_siem')
cur = conn.cursor()

print("=== DATOS EN experimento_latencias ===")
cur.execute("""
    SELECT grupo, COUNT(*),
           ROUND(AVG(mttd_seg)::numeric, 2) as mttd_media,
           ROUND(STDDEV_SAMP(mttd_seg)::numeric, 2) as mttd_desv,
           COUNT(mttd_seg) as mttd_no_nulos
    FROM experimento_latencias
    GROUP BY grupo
    ORDER BY grupo
""")
for row in cur.fetchall():
    print(f"  Grupo: {row[0]} | n={row[1]} | MTTD media={row[2]}s | desv={row[3]}s | no nulos={row[4]}")

print("\n=== PRIMERAS 5 FILAS (manual) ===")
cur.execute("""
    SELECT iteracion, mttd_seg, mttr_seg, t0_inyeccion, t1_deteccion, t2_respuesta
    FROM experimento_latencias
    WHERE grupo='manual'
    ORDER BY iteracion
    LIMIT 5
""")
for row in cur.fetchall():
    print(f"  iter={row[0]} | MTTD={row[1]}s | MTTR={row[2]}s | T0={row[3]} | T1={row[4]} | T2={row[5]}")

cur.close()
conn.close()