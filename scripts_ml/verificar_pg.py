import psycopg2

conn = psycopg2.connect(host='siem_postgres', user='admin', password='1234', dbname='tesis_siem')
cur = conn.cursor()

for grupo in ('manual', 'automatizado'):
    cur.execute("""
        SELECT COUNT(*),
               ROUND(AVG(mttr_seg)::numeric, 2),
               ROUND(STDDEV_SAMP(mttr_seg)::numeric, 2),
               ROUND(AVG(mttd_seg)::numeric, 2)
        FROM experimento_latencias
        WHERE grupo = %s AND mttr_seg IS NOT NULL
    """, (grupo,))
    n, avg_mttr, std_mttr, avg_mttd = cur.fetchone()
    print(f"Grupo {grupo}: n={n} | MTTR media={avg_mttr}s desv={std_mttr}s | MTTD media={avg_mttd}s")

cur.close()
conn.close()
