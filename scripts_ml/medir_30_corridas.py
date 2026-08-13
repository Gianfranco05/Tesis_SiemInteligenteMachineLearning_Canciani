"""
Corre el 'Escenario Tesis' N veces (default 30) para la validacion
estadistica de la Seccion 5.1.2 / Tabla 2 de la tesis.

A diferencia de correr motor_ml.py --loop (que vuelve a evaluar la MISMA
ventana deslizante de 5 minutos cada pocos segundos, generando filas
duplicadas y mezclando eventos de corridas consecutivas), este script
aisla cada corrida filtrando en Elasticsearch solo los eventos con
@timestamp posterior al inicio de ESA corrida puntual. Así cada fila del
CSV corresponde a una muestra independiente de ~113 eventos (85/15),
sin necesidad de borrar nada de Elasticsearch ni de esperar a que
expire una ventana de tiempo entre corridas.

No envia alertas a n8n/Telegram (evita 30 notificaciones reales); solo
mide precision/recall/f1 y las agrega al CSV, igual que haria
calcular_metricas() dentro de motor_ml.py.
"""
import csv
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(__file__))
os.chdir(os.path.dirname(__file__))

os.environ.setdefault("ES_HOST", "http://localhost:9200")

import motor_ml as ml  # noqa: E402

N_CORRIDAS = int(sys.argv[1]) if len(sys.argv) > 1 else 30
CSV_PATH = os.path.join(os.path.dirname(__file__), "resultados_clasificacion.csv")
EVENTOS_ESPERADOS = 113
TIMEOUT_INDEXADO = 90
POLL = 3


def contar_filas_csv():
    if not os.path.isfile(CSV_PATH):
        return 0
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        return sum(1 for _ in csv.reader(f)) - 1


def contar_eventos_es(desde: datetime) -> int:
    query = {
        "query": {
            "range": {
                "@timestamp": {"gte": desde.isoformat(), "lte": "now"}
            }
        }
    }
    es = ml.conectar_elasticsearch()
    r = es.count(index=ml.ES_INDEX, body=query)
    return r["count"]


def extraer_logs_ventana(desde: datetime) -> list[dict]:
    query = {
        "query": {
            "range": {
                "@timestamp": {"gte": desde.isoformat(), "lte": "now"}
            }
        },
        "size": 2000,
        "sort": [{"@timestamp": {"order": "asc"}}],
    }
    es = ml.conectar_elasticsearch()
    resultado = es.search(index=ml.ES_INDEX, body=query)
    hits = resultado.get("hits", {}).get("hits", [])
    return [h["_source"] for h in hits]


def disparar_escenario():
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    proc = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(__file__), "simulador_ataques.py")],
        input="6\n7\n",
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=60,
        env=env,
    )
    return proc.stdout, proc.stderr


def medir_una_corrida(i: int, total: int):
    t_inicio = datetime.now(timezone.utc) - timedelta(seconds=3)
    out, err = disparar_escenario()
    if "ESCENARIO GENERADO" not in out:
        print(f"[WARN corrida {i}] salida inesperada del simulador:\n{out[-1500:]}\n{err[-1500:]}")

    esperado = 0
    while esperado < TIMEOUT_INDEXADO:
        n = contar_eventos_es(t_inicio)
        if n >= EVENTOS_ESPERADOS:
            break
        time.sleep(POLL)
        esperado += POLL
    else:
        print(f"[ERROR corrida {i}] timeout esperando indexado. Eventos vistos: {contar_eventos_es(t_inicio)}")
        return False

    logs = extraer_logs_ventana(t_inicio)
    df_completo = ml.construir_features(logs)
    X, meta = ml.separar_features(df_completo)
    etiquetas_gt = ml.generar_etiquetas_poc(df_completo)
    X_escalado = ml.escalar_features(X)
    pred_if, scores_if = ml.ejecutar_isolation_forest(X_escalado)
    labels_dbscan = ml.ejecutar_dbscan(X_escalado)
    prediccion_final = ml.fusionar_predicciones(pred_if, labels_dbscan, freq_ip=X["freq_ip"].values)
    metricas = ml.calcular_metricas(etiquetas_gt, prediccion_final)  # ya escribe el CSV

    if not metricas:
        print(f"[ERROR corrida {i}] calcular_metricas devolvio vacio (sin anomalias en ground-truth).")
        return False

    print(f"[OK corrida {i}/{total}] eventos={len(logs)} "
          f"precision={metricas['precision']:.3f} recall={metricas['recall']:.3f} f1={metricas['f1_score']:.3f}")
    return True


def main():
    filas_iniciales = contar_filas_csv()
    print(f"[INFO] Filas iniciales en CSV: {filas_iniciales}. Corridas a ejecutar: {N_CORRIDAS}")

    exitosas = 0
    for i in range(1, N_CORRIDAS + 1):
        ok = medir_una_corrida(i, N_CORRIDAS)
        if ok:
            exitosas += 1
        else:
            print(f"[ABORT] Se detiene tras {i} corridas ({exitosas} exitosas). Revisa el error de arriba.")
            sys.exit(1)

    print(f"\n[DONE] {exitosas}/{N_CORRIDAS} corridas exitosas. Filas totales en CSV: {contar_filas_csv()}")


if __name__ == "__main__":
    main()
