# Experimento real de MTTD / MTTR — Guía de ejecución

Este kit hace que los tiempos de la sección 5.1.2 salgan **de verdad** de tu
PostgreSQL, tal como tu tesis afirma. Los números que obtengas reemplazan a los
valores actuales del documento (15.4 / 10.8 / t=2.32 / p=0.024), que hasta ahora
no tenían respaldo en el sistema.

> Regla de oro: lo que reportes en la tesis tiene que ser lo que imprima
> `analizar_experimento.py`. Si los números cambian (y van a cambiar), se
> actualiza el texto, no al revés.

---

## Paso 1 — Crear las tablas de auditoría (una sola vez)

Copiá `01_schema_experimento.sql` junto a tu `init_db/` y ejecutalo:

```bash
docker exec -i siem_postgres psql -U admin -d tesis_siem < 01_schema_experimento.sql
```

(ajustá el nombre del contenedor y usuario si difieren de tu `.env`).

## Paso 2 — Registrar la contramedida en n8n (provee T2 automático)

En tu workflow de respuesta (RU-4B), después del nodo que aplica el bloqueo
`iptables`, agregá un nodo **Postgres → Insert** sobre `respuestas_aplicadas`
con: `ip_origen` = la IP bloqueada, `accion` = 'bloqueo_iptables'.
Así el sistema deja el timestamp T2 en la auditoría inmutable.

> Si preferís no tocar n8n, podés medir T2 leyendo iptables por SSH; en ese caso
> avisame y te adapto el harness. La versión con tabla es la más limpia.

## Paso 3 — Variables de entorno

El harness lee del entorno. Antes de correr:

```bash
export POSTGRES_USER=admin POSTGRES_PASSWORD=1234 POSTGRES_DB=tesis_siem
export PG_HOST=127.0.0.1 PG_PORT=5432
export LOGSTASH_HOST=127.0.0.1 LOGSTASH_PORT=5000   # el puerto TCP de tu input Logstash
pip install psycopg2-binary scipy matplotlib
```

## Paso 4 — Correr el grupo AUTOMATIZADO (automático)

```bash
python medir_latencias.py --grupo automatizado --n 30
```

Inyecta 30 incidentes reales, espera la detección del motor ML y la confirmación
del bloqueo, y guarda T0/T1/T2 en PostgreSQL. No requiere intervención.

## Paso 5 — Correr el grupo MANUAL (reacción humana real)

```bash
python medir_latencias.py --grupo manual --n 30
```

Vas a vigilar Kibana y pulsar ENTER cuando detectes y cuando bloquearías. Esto
mide tu tiempo de reacción real como analista N1. Es la parte que solo podés
hacer vos: no se puede automatizar un humano sin falsear el dato.

> Consejo de honestidad metodológica: hacé estas 30 iteraciones en distintos
> momentos/días si querés sostener la afirmación de independencia temporal de la
> página 16. Si las hacés todas seguidas, **cambiá** ese párrafo para que
> describa lo que realmente hiciste.

## Paso 6 — Analizar y generar figuras

```bash
python analizar_experimento.py
```

Imprime el bloque "PARA LA TESIS" con medias, desvíos, t, df, p, IC 95% y
Shapiro-Wilk reales, y crea `figura1_boxplot_mttr.png` y
`figura2_histograma_mttd.png`.

---

## Plantilla para la sección 5.1.2 (rellenar con la salida real)

Reemplazá los `{{...}}` por los valores que imprima el análisis.

> Para garantizar que la mejora en los tiempos de respuesta no fuera producto del
> azar, se realizó un análisis de significancia estadística comparando el Tiempo
> Medio de Respuesta (MTTR) entre ambos grupos, sobre {{N}} muestras
> independientes por enfoque, cuyos registros de tiempo fueron extraídos de la
> auditoría en PostgreSQL.
>
> - Grupo de Control (Manual): media de MTTR = {{MEDIA_CONTROL}} s
>   (desv. estándar s = {{DESV_CONTROL}} s).
> - Grupo Experimental (Automatizado SOAR): media de MTTR =
>   {{MEDIA_EXP}} s (desv. estándar s = {{DESV_EXP}} s).
>
> La normalidad de las distribuciones se evaluó mediante la prueba de
> Shapiro-Wilk (control: W = {{W_CONTROL}}, p = {{P_SW_CONTROL}};
> experimental: W = {{W_EXP}}, p = {{P_SW_EXP}}). Aplicando la prueba T de
> Student para muestras independientes (corrección de Welch, df ≈ {{DF}}), se
> obtuvo t = {{T}} con un nivel de significancia p = {{P}}. El intervalo de
> confianza al 95% para la diferencia de medias se sitúa en
> [{{IC_INF}}, {{IC_SUP}}] s. Dado que p {{<o≥}} 0.05,
> {{se rechaza / no se rechaza}} la hipótesis nula.
>
> La dispersión y la forma de las distribuciones se ilustran en la Figura 1
> (Boxplot comparativo de MTTR) y la Figura 2 (Histograma de distribución de
> MTTD).

## Ajuste obligatorio en la página 16 (metodología)

Dos correcciones de honestidad, ahora que la medición es real:

1. Tu texto dice que **no** aplicaste Shapiro-Wilk y que asumiste normalidad por
   el Teorema del Límite Central. Como el análisis ahora **sí** corre
   Shapiro-Wilk, reemplazá esa "limitación reconocida" por el reporte del
   resultado real de la prueba.
2. La afirmación de "30 iteraciones distribuidas a lo largo de dos semanas":
   dejala solo si efectivamente las distribuís así. Si no, describí el protocolo
   que realmente seguiste.

## Recordatorio: sesgo del observador en conclusiones (6.1)

La página 16 promete retomar el sesgo del observador en las conclusiones. Sigue
sin estar en 6.1. Cuando cierres los números, agregamos ese párrafo para cumplir
la promesa.
