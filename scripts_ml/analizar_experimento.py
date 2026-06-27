#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════
#  analizar_experimento.py
#  Lee las latencias REALES desde PostgreSQL, calcula MTTD/MTTR,
#  corre la prueba T de Student y Shapiro-Wilk, y genera las dos
#  figuras (Figura 1: Boxplot MTTR · Figura 2: Histograma MTTD).
#
#  Imprime un bloque "PARA LA TESIS" con los números reales listos
#  para pegar en la sección 5.1.2.
#
#  Uso:  python analizar_experimento.py
#  Salidas: figura1_boxplot_mttr.png, figura2_histograma_mttd.png
# ════════════════════════════════════════════════════════════════

import os
import numpy as np
import psycopg2
from scipy import stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PG = dict(
    host=os.getenv("PG_HOST", "127.0.0.1"),
    port=int(os.getenv("PG_PORT", "5432")),
    user=os.getenv("POSTGRES_USER", "admin"),
    password=os.getenv("POSTGRES_PASSWORD", "1234"),
    dbname=os.getenv("POSTGRES_DB", "tesis_siem"),
)


def traer(metrica):
    """Devuelve dict {grupo: np.array} con la métrica pedida ('mttd_seg' o 'mttr_seg')."""
    conn = psycopg2.connect(**PG)
    cur = conn.cursor()
    out = {}
    for grupo in ("manual", "automatizado"):
        cur.execute(
            f"SELECT {metrica} FROM experimento_latencias "
            f"WHERE grupo=%s AND {metrica} IS NOT NULL ORDER BY iteracion;",
            (grupo,),
        )
        out[grupo] = np.array([r[0] for r in cur.fetchall()], dtype=float)
    cur.close(); conn.close()
    return out


def describir(arr):
    return dict(n=len(arr), media=arr.mean(), desv=arr.std(ddof=1))


def prueba_t(control, experimental):
    t, p = stats.ttest_ind(control, experimental, equal_var=False)  # Welch
    # IC 95% de la diferencia de medias (Welch)
    d = control.mean() - experimental.mean()
    se = np.sqrt(control.var(ddof=1)/len(control) + experimental.var(ddof=1)/len(experimental))
    df = (se**4) / (
        (control.var(ddof=1)/len(control))**2 / (len(control)-1) +
        (experimental.var(ddof=1)/len(experimental))**2 / (len(experimental)-1)
    )
    tcrit = stats.t.ppf(0.975, df)
    ic = (d - tcrit*se, d + tcrit*se)
    return t, p, df, ic


def main():
    mttr = traer("mttr_seg")
    mttd = traer("mttd_seg")

    if len(mttr["manual"]) == 0 or len(mttr["automatizado"]) == 0:
        print("⚠ No hay datos suficientes todavía. Corré medir_latencias.py para ambos grupos.")
        return

    # ── Estadística MTTR ──────────────────────────────────────────
    c, e = mttr["manual"], mttr["automatizado"]
    dc, de = describir(c), describir(e)
    t, p, df, ic = prueba_t(c, e)
    sh_c = stats.shapiro(c) if len(c) >= 3 else (float("nan"), float("nan"))
    sh_e = stats.shapiro(e) if len(e) >= 3 else (float("nan"), float("nan"))
    var = 100 * (de["media"] - dc["media"]) / dc["media"]

    # ── Figura 1: Boxplot MTTR ────────────────────────────────────
    fig, ax = plt.subplots(figsize=(7, 5))
    bp = ax.boxplot([c, e], labels=["Manual\n(control)", "Automatizado\n(SOAR)"],
                    patch_artist=True, widths=0.55)
    for patch in bp["boxes"]:
        patch.set_facecolor("white"); patch.set_edgecolor("black")
    for el in ("whiskers", "caps", "medians"):
        for line in bp[el]:
            line.set_color("black")
    ax.set_ylabel("MTTR (segundos)")
    ax.set_title("Figura 1. Boxplot comparativo del MTTR por enfoque")
    ax.grid(axis="y", linestyle=":", color="0.7")
    fig.tight_layout()
    fig.savefig("figura1_boxplot_mttr.png", dpi=200)
    plt.close(fig)

    # ── Figura 2: Histograma MTTD ─────────────────────────────────
    cm, em = mttd["manual"], mttd["automatizado"]
    fig, ax = plt.subplots(figsize=(7, 5))
    bins = np.histogram_bin_edges(np.concatenate([cm, em]), bins="auto")
    ax.hist(cm, bins=bins, alpha=0.6, label="Manual (control)",
            edgecolor="black", color="0.75")
    ax.hist(em, bins=bins, alpha=0.6, label="Automatizado (SOAR)",
            edgecolor="black", color="0.35")
    ax.set_xlabel("MTTD (segundos)")
    ax.set_ylabel("Frecuencia")
    ax.set_title("Figura 2. Histograma de distribución del MTTD")
    ax.legend()
    ax.grid(axis="y", linestyle=":", color="0.7")
    fig.tight_layout()
    fig.savefig("figura2_histograma_mttd.png", dpi=200)
    plt.close(fig)

    # ── Bloque listo para la tesis ────────────────────────────────
    print("\n" + "═" * 64)
    print("  RESULTADOS REALES — PARA PEGAR EN LA SECCIÓN 5.1.2")
    print("═" * 64)
    print(f"MTTR Control (Manual):       media = {dc['media']:.2f} s   "
          f"desv = {dc['desv']:.2f} s   (n={dc['n']})")
    print(f"MTTR Experimental (SOAR):    media = {de['media']:.2f} s   "
          f"desv = {de['desv']:.2f} s   (n={de['n']})")
    print(f"Variación MTTR:              {var:+.1f}%")
    print(f"Prueba T (Welch):            t = {t:.2f}   df ≈ {df:.1f}   p = {p:.4f}")
    print(f"IC 95% de la diferencia:     [{ic[0]:.2f}, {ic[1]:.2f}] s")
    print(f"Shapiro-Wilk control:        W = {sh_c[0]:.3f}   p = {sh_c[1]:.4f}")
    print(f"Shapiro-Wilk experimental:   W = {sh_e[0]:.3f}   p = {sh_e[1]:.4f}")
    print(f"Decisión (α=0.05):           "
          f"{'se RECHAZA H0 (diferencia significativa)' if p < 0.05 else 'NO se rechaza H0'}")
    print("Figuras generadas: figura1_boxplot_mttr.png, figura2_histograma_mttd.png")
    print("═" * 64)


if __name__ == "__main__":
    main()
