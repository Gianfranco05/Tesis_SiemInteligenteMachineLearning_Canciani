"""
motor_ml.py — Motor de Machine Learning Real
SIEM Inteligente con ML | UTN FRM | Gianfranco Canciani

Este módulo implementa la detección de anomalías usando dos algoritmos
complementarios de aprendizaje no supervisado:
  - Isolation Forest: detecta eventos atípicos multidimensionales
  - DBSCAN: detecta ráfagas de densidad (ataques masivos como fuerza bruta)

Funciona en dos modos:
  - Modo único (por defecto): analiza una vez y termina
  - Modo loop (--loop): analiza cada N segundos de forma continua

Cómo ejecutarlo desde tu PC (con el stack Docker levantado):
  pip install -r requirements.txt
  python motor_ml.py

Cómo ejecutarlo desde el contenedor ml-python:
  docker exec -it siem_ml bash
  pip install -r /app/requirements.txt
  python /app/motor_ml.py
"""

import os
import sys
import time
import logging
import argparse
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
import requests
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

# ──────────────────────────────────────────────
# CONFIGURACIÓN — variables de entorno o defaults
# ──────────────────────────────────────────────
# Cuando corrés desde tu PC: ES_HOST=http://localhost:9200
# Cuando corrés desde dentro del contenedor siem_ml: ES_HOST=http://elasticsearch:9200
ES_HOST = os.getenv("ES_HOST", "http://siem_elasticsearch:9200")
WEBHOOK_URL  = os.getenv("WEBHOOK_URL",  "http://siem_n8n:5678/webhook/alerta-ml")
LOOP_SECONDS = int(os.getenv("LOOP_SECONDS", "60"))   
ES_INDEX     = os.getenv("ES_INDEX",     "eventos-seguridad-*")
VENTANA_MIN  = int(os.getenv("VENTANA_MIN", "30"))    

# Hiperparámetros calibrados (tal como describe la tesis)
IF_CONTAMINATION = 0.18   # proporción esperada de anomalías (~15% sintético + margen de seguridad)
IF_N_ESTIMATORS  = 100    # número de árboles
IF_RANDOM_STATE  = 42
DBSCAN_EPS        = 1.5   # distancia máxima de vecindad (calibrada sobre features escaladas)
DBSCAN_MIN_SAMPLES = 3    # mínimo de eventos para formar un cluster
DENSIDAD_UMBRAL_FREQ = 5  # freq_ip mínima para considerar una IP como ráfaga (regla determinística)

# ──────────────────────────────────────────────
# LOGGING — produce trazas auditables
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("motor_ml.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("motor_ml")


# ══════════════════════════════════════════════
# 1. EXTRACCIÓN DE DATOS DESDE ELASTICSEARCH
# ══════════════════════════════════════════════

def conectar_elasticsearch() -> Elasticsearch:
    """Devuelve un cliente ES. Falla explícitamente si no hay conexión."""
    es = Elasticsearch(ES_HOST, request_timeout=10)
    if not es.ping():
        raise ConnectionError(
            f"No se pudo conectar a Elasticsearch en {ES_HOST}. "
            "¿Está levantado el contenedor? Ejecutá: docker compose up -d"
        )
    log.info(f"Conectado a Elasticsearch en {ES_HOST}")
    return es


def extraer_logs(es: Elasticsearch, ventana_minutos: int = VENTANA_MIN) -> list[dict]:
    """
    Consulta los últimos `ventana_minutos` minutos de logs indexados.
    Devuelve una lista de documentos crudos (_source).
    """
    desde = datetime.now(timezone.utc) - timedelta(minutes=ventana_minutos)
    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": desde.isoformat(),
                    "lte": "now",
                }
            }
        },
        "size": 2000,
        "sort": [{"@timestamp": {"order": "asc"}}],
    }

    try:
        resultado = es.search(index=ES_INDEX, body=query)
    except Exception as e:
        log.warning(f"Error al consultar Elasticsearch: {e}. Reintentando más tarde.")
        return []

    hits = resultado.get("hits", {}).get("hits", [])
    log.info(f"Logs extraídos de ES (últimos {ventana_minutos} min): {len(hits)}")
    return [h["_source"] for h in hits]


# ══════════════════════════════════════════════
# 2. INGENIERÍA DE FEATURES
# ══════════════════════════════════════════════

def construir_features(logs: list[dict]) -> pd.DataFrame:
    """
    Convierte los documentos JSON en un DataFrame numérico.
    Cada fila = un evento de log con las features que usan los modelos.

    Features:
      - hora_del_dia:   0-23, captura accesos en horario anómalo
      - es_fallo_ssh:   1 si el log contiene "Failed", 0 si no
      - es_exitoso_ssh: 1 si el log contiene "Accepted"
      - puerto:         número de puerto (22 = SSH habitual, otros = anómalos)
      - lon_mensaje:    longitud del campo message (proxy de entropía)
      - es_spike:       1 si el log contiene "SPIKE_CPU"
    """
    registros = []

    import re as _re

    for doc in logs:
        mensaje = doc.get("message", "") or ""
        timestamp_str = doc.get("@timestamp", "")

        # Parseo de hora: PRIORIDAD al horario que viene DENTRO del mensaje
        # (formato syslog "Jun 26 03:15:00"), porque @timestamp de Elasticsearch
        # es la hora de INGESTA, no la del evento. Esto es clave para detectar
        # accesos nocturnos (RU-2): el simulador marca 03:15 en el texto del log.
        hora = None
        m = _re.search(r"\b(\d{2}):(\d{2}):(\d{2})\b", mensaje)
        if m:
            try:
                hora = int(m.group(1))
            except (ValueError, TypeError):
                hora = None
        if hora is None:
            try:
                ts = pd.to_datetime(timestamp_str, utc=True)
                hora = ts.hour
            except Exception:
                hora = datetime.now().hour

        # Puerto: puede venir como string o int
        try:
            puerto = int(doc.get("port", 22) or 22)
        except (ValueError, TypeError):
            puerto = 22

        registros.append({
            "hora_del_dia":   hora,
            "es_fallo_ssh":   1 if "Failed" in mensaje  else 0,
            "es_exitoso_ssh": 1 if "Accepted" in mensaje else 0,
            "puerto":         puerto,
            "lon_mensaje":    len(mensaje),
            "es_spike":       1 if "SPIKE_CPU" in mensaje else 0,
            # Guardamos campos originales fuera del DataFrame para el reporte
            "_source_ip":     doc.get("source_ip", ""),
            "_message":       mensaje[:120],
        })

    df = pd.DataFrame(registros)

    # FEATURE freq_ip: cuántas veces aparece cada IP de origen en la ventana.
    # Esta es la señal clave para detectar ráfagas (fuerza bruta = muchos
    # eventos desde la misma IP) frente a tráfico legítimo (pocos por IP).
    if len(df) > 0 and "_source_ip" in df.columns:
        # Solo contamos IPs reales. Los eventos sin IP (cron, systemd, dns)
        # NO se agrupan como un grupo gigante (eso falsearía la densidad);
        # se les asigna freq_ip=1 (neutro), como un evento aislado normal.
        ips_validas = df["_source_ip"][df["_source_ip"] != ""]
        conteo_ip = ips_validas.value_counts().to_dict()
        df["freq_ip"] = df["_source_ip"].map(lambda ip: conteo_ip.get(ip, 1) if ip != "" else 1)
    else:
        df["freq_ip"] = 1

    return df


def separar_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Devuelve (features_numericas, metadatos).
    Los modelos ML solo ven las columnas numéricas.
    """
    cols_ml = ["hora_del_dia", "es_fallo_ssh", "es_exitoso_ssh",
               "puerto", "lon_mensaje", "es_spike", "freq_ip"]
    cols_meta = ["_source_ip", "_message"]
    return df[cols_ml].copy(), df[cols_meta].copy()


# ══════════════════════════════════════════════
# 3. ETIQUETADO GROUND-TRUTH PARA LA PoC
# ══════════════════════════════════════════════

def generar_etiquetas_poc(df: pd.DataFrame) -> np.ndarray:
    """
    Como el dataset es de laboratorio con logs sintéticos conocidos,
    podemos generar etiquetas ground-truth basadas en las reglas de negocio
    que el simulador usó para inyectar ataques.

    Esto permite calcular Precision/Recall/F1 reales.

    Criterios de anomalía (etiqueta = 1):
      - Fallo SSH: es_fallo_ssh == 1  (inyectado por RU-1)
      - Acceso nocturno exitoso: es_exitoso_ssh==1 AND hora entre 0-6
      - Spike de CPU: es_spike == 1

    Todo lo demás = 0 (normal)
    """
    etiquetas = np.zeros(len(df), dtype=int)

    for i, row in df.iterrows():
        if row["es_fallo_ssh"] == 1:
            etiquetas[i] = 1
        elif row["es_exitoso_ssh"] == 1 and row["hora_del_dia"] in range(0, 7):
            etiquetas[i] = 1
        elif row["es_spike"] == 1:
            etiquetas[i] = 1

    anomalias = int(etiquetas.sum())
    log.info(f"Ground-truth generado: {anomalias} anomalías / {len(etiquetas) - anomalias} normales")
    return etiquetas


# ══════════════════════════════════════════════
# 3.5 ESCALADO DE FEATURES (StandardScaler)
# ══════════════════════════════════════════════

def escalar_features(X: pd.DataFrame) -> np.ndarray:
    """
    Normaliza las features con StandardScaler (media 0, desvío 1).

    CRÍTICO: sin escalado, features de rango amplio como 'puerto' (0-65535)
    dominan la distancia euclidiana y rompen DBSCAN, que pasa a marcar casi
    todo como ruido. El escalado pone todas las features en la misma escala,
    permitiendo que cada una aporte equitativamente a la detección.
    """
    scaler = StandardScaler()
    X_escalado = scaler.fit_transform(X)
    log.info(f"Features escaladas con StandardScaler | shape={X_escalado.shape}")
    return X_escalado


# ══════════════════════════════════════════════
# 4. ISOLATION FOREST — Detección de Outliers
# ══════════════════════════════════════════════

def ejecutar_isolation_forest(
    X,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Entrena y predice con Isolation Forest.

    Devuelve:
      - predicciones: array donde -1 = anomalía, 1 = normal
      - scores:       decision_function (más negativo = más anómalo)
    """
    log.info(
        f"Entrenando Isolation Forest | "
        f"n_estimators={IF_N_ESTIMATORS}, contamination={IF_CONTAMINATION}"
    )

    modelo = IsolationForest(
        n_estimators=IF_N_ESTIMATORS,
        contamination=IF_CONTAMINATION,
        random_state=IF_RANDOM_STATE,
        n_jobs=-1,   # usa todos los núcleos disponibles
    )

    predicciones = modelo.fit_predict(X)
    scores       = modelo.decision_function(X)

    n_anomalias = (predicciones == -1).sum()
    log.info(f"Isolation Forest detectó {n_anomalias} anomalías sobre {len(X)} eventos")
    return predicciones, scores


# ══════════════════════════════════════════════
# 5. DBSCAN — Detección de Ráfagas de Densidad
# ══════════════════════════════════════════════

def ejecutar_dbscan(X) -> np.ndarray:
    """
    Agrupa eventos por densidad temporal/espacial.
    Los eventos clasificados como -1 (ruido) son candidatos a anomalía.

    DBSCAN es especialmente útil para detectar ataques de fuerza bruta
    donde hay una ráfaga de eventos en muy poco tiempo.

    Devuelve array de etiquetas: -1 = ruido (anómalo), >=0 = cluster normal
    """
    log.info(
        f"Ejecutando DBSCAN | eps={DBSCAN_EPS}, min_samples={DBSCAN_MIN_SAMPLES}"
    )

    modelo  = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES)
    labels  = modelo.fit_predict(X)

    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_ruido    = (labels == -1).sum()
    log.info(f"DBSCAN → {n_clusters} clusters, {n_ruido} eventos como ruido (anómalos)")
    return labels


# ══════════════════════════════════════════════
# 6. FUSIÓN DE MODELOS Y DECISIÓN FINAL
# ══════════════════════════════════════════════

def fusionar_predicciones(
    pred_if: np.ndarray,
    labels_dbscan: np.ndarray,
    freq_ip: np.ndarray = None,
) -> np.ndarray:
    """
    Combina tres señales con lógica OR. Un evento es anómalo si AL MENOS UNA
    de las siguientes lo marca:

      1. Isolation Forest  -> outliers multidimensionales
      2. DBSCAN            -> ruido fuera de clusters densos
      3. Regla de densidad -> IPs con ráfaga de eventos (freq_ip >= umbral)

    La regla de densidad es determinística y complementa a los modelos no
    supervisados: garantiza capturar ataques de fuerza bruta, donde una misma
    IP genera muchos eventos idénticos en la ventana (un cluster denso que
    Isolation Forest tiende a considerar "normal" por su propia densidad).
    Este enfoque híbrido (modelos estadísticos + regla de correlación) replica
    el funcionamiento de un SIEM real y estabiliza el recall en ~100%.

    Esto da mayor cobertura (recall) a costa de algo de precisión, lo cual es
    preferible en seguridad: mejor alertar de más que perder una amenaza.

    Devuelve array binario: 1 = anomalía final, 0 = normal
    """
    anomalia_if     = (pred_if == -1).astype(int)
    anomalia_dbscan = (labels_dbscan == -1).astype(int)

    if freq_ip is not None:
        anomalia_densidad = (np.asarray(freq_ip) >= DENSIDAD_UMBRAL_FREQ).astype(int)
    else:
        anomalia_densidad = np.zeros_like(anomalia_if)

    # OR de las tres señales
    fusion = np.maximum.reduce([anomalia_if, anomalia_dbscan, anomalia_densidad])

    log.info(
        f"Fusión (OR): IF={anomalia_if.sum()} | DBSCAN={anomalia_dbscan.sum()} "
        f"| Densidad={anomalia_densidad.sum()} | Total final={fusion.sum()}"
    )
    return fusion


# ══════════════════════════════════════════════
# 7. MÉTRICAS DE EVALUACIÓN REALES
# ══════════════════════════════════════════════

def calcular_metricas(
    etiquetas_reales: np.ndarray,
    predicciones_finales: np.ndarray,
) -> dict:
    """
    Calcula Precision, Recall, F1-Score y la matriz de confusión.
    Estas son las métricas que van a la Tabla 2 de la tesis.
    """
    if etiquetas_reales.sum() == 0:
        log.warning("No hay anomalías en el ground-truth. Métricas no calculables.")
        return {}

    precision = precision_score(etiquetas_reales, predicciones_finales, zero_division=0)
    recall    = recall_score(etiquetas_reales, predicciones_finales, zero_division=0)
    f1        = f1_score(etiquetas_reales, predicciones_finales, zero_division=0)
    cm        = confusion_matrix(etiquetas_reales, predicciones_finales)

    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    metricas = {
        "precision":  round(precision, 4),
        "recall":     round(recall, 4),
        "f1_score":   round(f1, 4),
        "verdaderos_positivos":  int(tp),
        "falsos_positivos":      int(fp),
        "falsos_negativos":      int(fn),
        "verdaderos_negativos":  int(tn),
        "tasa_falsos_positivos": round(fp / (fp + tn) if (fp + tn) > 0 else 0, 4),
    }

    # Imprimir tabla de métricas en consola (útil para la defensa)
    print("\n" + "=" * 55)
    print("  📊  MÉTRICAS DEL MOTOR DE MACHINE LEARNING")
    print("=" * 55)
    print(f"  Precision (Exactitud de alertas):  {precision:.1%}")
    print(f"  Recall    (Cobertura de amenazas): {recall:.1%}")
    print(f"  F1-Score  (Balance P/R):           {f1:.3f}")
    print(f"  Tasa Falsos Positivos:             {metricas['tasa_falsos_positivos']:.1%}")
    print("-" * 55)
    print(f"  ✅ Verdaderos Positivos (amenazas detectadas): {tp}")
    print(f"  ❌ Falsos Positivos     (falsas alarmas):      {fp}")
    print(f"  ⚠️  Falsos Negativos     (amenazas perdidas):   {fn}")
    print(f"  ✅ Verdaderos Negativos (tráfico limpio OK):   {tn}")
    print("=" * 55 + "\n")

    log.info(f"Métricas → Precision={precision:.3f} | Recall={recall:.3f} | F1={f1:.3f}")
    return metricas


# ══════════════════════════════════════════════
# 8. ENVÍO DE ALERTAS A N8N (SOAR)
# ══════════════════════════════════════════════

def enviar_alerta_a_n8n(
    ip_origen: str,
    score_riesgo: float,
    mensaje_original: str,
    metricas: dict,
) -> bool:
    """
    Envía una alerta real al webhook de n8n para que el orquestador SOAR
    la procese, enriquezca con OSINT, notifique por Telegram y espere
    la decisión del analista (Human-in-the-Loop).
    """
    payload = {
        "regla":            "RU-4",
        "algoritmo":        "Isolation Forest + DBSCAN",
        "tipo_patron":      "Anomalía Multidimensional Real",
        "ip_origen":        ip_origen or "desconocida",
        "score_riesgo":     score_riesgo,
        "mensaje_log":      mensaje_original[:200],
        "timestamp_deteccion": datetime.now().isoformat(),
        "metricas_modelo":  metricas,
        "accion":           "Pendiente de validación HITL",
    }

    log.info(f"Enviando alerta a n8n → IP: {ip_origen} | Score: {score_riesgo:.4f}")

    try:
        r = requests.post(WEBHOOK_URL, json=payload, timeout=10)
        if r.status_code == 200:
            log.info("✅ n8n recibió la alerta correctamente.")
            return True
        else:
            log.warning(f"n8n respondió con código {r.status_code}: {r.text[:200]}")
            return False
    except requests.exceptions.ConnectionError:
        log.error(
            f"No se pudo conectar al webhook de n8n ({WEBHOOK_URL}). "
            "¿Está activo el workflow RU-4 en n8n?"
        )
        return False
    except Exception as e:
        log.error(f"Error inesperado al enviar webhook: {e}")
        return False


# ══════════════════════════════════════════════
# 9. PIPELINE COMPLETO
# ══════════════════════════════════════════════

def ejecutar_ciclo_ml() -> dict | None:
    """
    Ejecuta un ciclo completo del motor ML:
      1. Conectar a ES
      2. Extraer logs recientes
      3. Construir features
      4. Correr Isolation Forest
      5. Correr DBSCAN
      6. Fusionar predicciones
      7. Calcular métricas
      8. Enviar anomalías a n8n
    """
    print("\n" + "═" * 55)
    print(f"  🧠  MOTOR ML — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 55)

    # ── PASO 1: Conexión ──────────────────────────────────
    try:
        es = conectar_elasticsearch()
    except ConnectionError as e:
        log.error(str(e))
        return None

    # ── PASO 2: Extracción de logs ────────────────────────
    logs_crudos = extraer_logs(es, ventana_minutos=VENTANA_MIN)

    if len(logs_crudos) < 10:
        log.warning(
            f"Solo {len(logs_crudos)} logs en los últimos {VENTANA_MIN} minutos. "
            "Necesitás correr el simulador primero para poblar Elasticsearch."
        )
        print(
            "\n💡 TIP: Corré primero el simulador_ataques.py (opciones 1-3) "
            "para inyectar logs de prueba, luego ejecutá el motor ML.\n"
        )
        return None

    # ── PASO 3: Ingeniería de features ───────────────────
    df_completo  = construir_features(logs_crudos)
    X, meta      = separar_features(df_completo)
    etiquetas_gt = generar_etiquetas_poc(df_completo)

    # ── PASO 3.5: Escalado de features ───────────────────
    X_escalado   = escalar_features(X)

    # ── PASO 4: Isolation Forest (sobre features escaladas) ─
    pred_if, scores_if = ejecutar_isolation_forest(X_escalado)

    # ── PASO 5: DBSCAN (sobre features escaladas) ─────────
    labels_dbscan = ejecutar_dbscan(X_escalado)

    # ── PASO 6: Fusión ────────────────────────────────────
    prediccion_final = fusionar_predicciones(pred_if, labels_dbscan, freq_ip=X["freq_ip"].values)

    # ── PASO 7: Métricas reales ───────────────────────────
    metricas = calcular_metricas(etiquetas_gt, prediccion_final)

    # ── PASO 8: Enviar anomalías a n8n ───────────────────
    indices_anomalos = np.where(prediccion_final == 1)[0]

    if len(indices_anomalos) == 0:
        log.info("No se detectaron anomalías en esta ventana. Sistema estable.")
        return metricas

    log.info(f"Procesando {len(indices_anomalos)} anomalías para enviar a n8n...")

    # Enviamos solo la anomalía con el score más alto para no saturar el SOAR
    # (en producción se implementaría una cola, ver Sección 7.1 de la tesis)
    scores_anomalos = scores_if[indices_anomalos]
    idx_peor        = indices_anomalos[np.argmin(scores_anomalos)]  # más negativo = más anómalo

    ip_detectada     = meta.iloc[idx_peor]["_source_ip"]
    mensaje_detectado = meta.iloc[idx_peor]["_message"]
    score_final      = round(abs(float(scores_if[idx_peor])), 4)

    enviar_alerta_a_n8n(ip_detectada, score_final, mensaje_detectado, metricas)

    return metricas


# ══════════════════════════════════════════════
# 10. PUNTO DE ENTRADA
# ══════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Motor ML real — Isolation Forest + DBSCAN para SIEM"
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help=f"Ejecutar en modo continuo cada {LOOP_SECONDS}s (variable LOOP_SECONDS)",
    )
    args = parser.parse_args()

    if args.loop:
        log.info(f"Modo LOOP activado: ejecutando cada {LOOP_SECONDS} segundos.")
        print(f"Motor ML corriendo en loop cada {LOOP_SECONDS}s. Ctrl+C para detener.\n")
        while True:
            try:
                ejecutar_ciclo_ml()
                log.info(f"Próximo análisis en {LOOP_SECONDS} segundos...")
                time.sleep(LOOP_SECONDS)
            except KeyboardInterrupt:
                log.info("Motor ML detenido por el usuario.")
                sys.exit(0)
    else:
        # Modo único: analiza una vez y termina
        resultado = ejecutar_ciclo_ml()
        if resultado:
            log.info("Ciclo ML completado exitosamente.")
        else:
            log.warning("Ciclo ML completado sin resultados (ver mensajes arriba).")


if __name__ == "__main__":
    main()
