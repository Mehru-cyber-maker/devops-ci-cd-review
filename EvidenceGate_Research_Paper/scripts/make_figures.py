"""Publication-style figures derived from saved observations."""

import csv
import json
import os
from pathlib import Path
import tempfile

os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir())/"evidencegate-research-mpl"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/"figures"
OUT.mkdir(exist_ok=True)
SUMMARY = json.loads((ROOT/"results"/"summary.json").read_text())
NAVY, TEAL, ORANGE = "#19394f", "#087f77", "#c56a3b"
PALE, GRAY = "#edf3f7", "#607486"
COLORS = ["#8396a7", ORANGE, TEAL]
MODES = ["presence_only", "without_artifact_binding", "evidencegate"]
LABELS = ["Presence", "Ablation", "Full"]
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.titlesize": 12,
                     "axes.labelsize": 10, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.edgecolor": "#c2cdd6", "text.color": NAVY, "axes.labelcolor": NAVY,
                     "xtick.color": GRAY, "ytick.color": GRAY, "svg.fonttype": "none",
                     "pdf.fonttype": 42, "savefig.facecolor": "white"})


def save(fig, name):
    for ext in ["png", "svg", "pdf"]:
        path = OUT/(name+"."+ext)
        fig.savefig(path, dpi=300, bbox_inches="tight", pad_inches=.12)
        if ext == "svg":
            path.write_text("\n".join(line.rstrip() for line in path.read_text().splitlines())+"\n", encoding="utf-8")
    plt.close(fig)


def box(ax, x, y, width, height, text, dark=False):
    ax.add_patch(FancyBboxPatch((x,y), width, height, boxstyle="round,pad=0.02,rounding_size=0.08",
                               facecolor=NAVY if dark else PALE, edgecolor="#bacdd9", linewidth=1))
    ax.text(x+width/2, y+height/2, text, ha="center", va="center", color="white" if dark else NAVY, fontsize=10, linespacing=1.55)


def arrow(ax, start, end):
    ax.add_patch(FancyArrowPatch(start,end,arrowstyle="-|>",mutation_scale=12,color=GRAY,linewidth=1.3))


def architecture():
    fig,ax=plt.subplots(figsize=(8,3.9))
    ax.set(xlim=(0,11),ylim=(0,5));ax.axis("off")
    box(ax,.25,3.25,2.55,.75,"SLSA provenance\nBuild and source claims")
    box(ax,.25,2.12,2.55,.75,"CycloneDX SBOM\nRoot artifact hash")
    box(ax,.25,.99,2.55,.75,"Normalized scan\nSubject, time, findings")
    box(ax,3.8,3.83,3.05,.8,"Independent release digest\nand configured policy")
    box(ax,3.8,1.65,3.05,1.15,"EvidenceGate\n10 explicit consistency\nand policy checks",True)
    box(ax,7.95,2.7,2.5,.9,"PASS / BLOCK\nRule IDs and actions")
    box(ax,7.95,1.15,2.5,.9,"JSON · CSV · HTML\nDashboard / CLI")
    for y in [3.625,2.495,1.365]:arrow(ax,(2.83,y),(3.76,2.22))
    arrow(ax,(5.325,3.8),(5.325,2.84));arrow(ax,(6.9,2.3),(7.9,3.15));arrow(ax,(6.9,2.1),(7.9,1.6))
    ax.text(5.5,.23,"Evidence authenticity and scanner correctness must be established externally.",ha="center",color=GRAY,fontsize=9)
    save(fig,"figure_01_architecture")


def detection():
    fig,axes=plt.subplots(1,2,figsize=(8,3.8),layout="constrained")
    for ax,dataset,title in zip(axes,["fixture27","factorial64"],["Functional fixtures\n22 faulty cases","Factorial combinations\n63 faulty cases"]):
        metrics=[next(m for m in SUMMARY["metrics"] if m["dataset"]==dataset and m["mode"]==mode) for mode in MODES]
        values=[100*m["recall"] for m in metrics]
        bars=ax.bar(LABELS,values,color=COLORS,width=.58)
        ax.set(ylim=(0,117),ylabel="Faulty cases blocked (%)",title=title,yticks=[0,25,50,75,100])
        ax.yaxis.grid(True,alpha=.2);ax.set_axisbelow(True)
        for bar,m,value in zip(bars,metrics,values):
            ax.text(bar.get_x()+bar.get_width()/2,value+3,f"{m['true_blocks']}/{m['true_blocks']+m['false_accepts']}\n({value:.1f}%)",ha="center",va="bottom",fontsize=10)
    save(fig,"figure_02_fault_detection")


def confusion():
    fig,axes=plt.subplots(1,3,figsize=(8,3.1),layout="constrained")
    maximum=22
    for ax,mode,label in zip(axes,MODES,LABELS):
        m=next(m for m in SUMMARY["metrics"] if m["dataset"]=="fixture27" and m["mode"]==mode)
        array=np.array([[m["true_blocks"],m["false_accepts"]],[m["false_blocks"],m["true_accepts"]]])
        ax.imshow(array,cmap="Blues",vmin=0,vmax=maximum)
        ax.set(xticks=[0,1],xticklabels=["BLOCK","PASS"],yticks=[0,1],yticklabels=["Faulty (22)","Valid (5)"],title=label,xlabel="Observed decision")
        if mode != "presence_only":
            ax.set_yticklabels([])
        for (i,j),value in np.ndenumerate(array):
            ax.text(j,i,str(value),ha="center",va="center",fontsize=19,fontweight="bold",color="white" if value>maximum*.55 else NAVY)
    axes[0].set_ylabel("Constructed case label")
    save(fig,"figure_03_confusion_matrices")


def category_heatmap():
    with (ROOT/"results"/"decisions.csv").open() as handle:rows=list(csv.DictReader(handle))
    categories=["Missing evidence","Record structure","Artifact binding","Builder and source","Scan time","Vulnerability policy"]
    values=np.zeros((len(categories),3));counts={}
    for i,category in enumerate(categories):
        for j,mode in enumerate(MODES):
            selected=[r for r in rows if r["dataset"]=="fixture27" and r["category"]==category and r["mode"]==mode]
            blocked=sum(r["decision"]=="BLOCK" for r in selected)
            counts[i,j]=(blocked,len(selected));values[i,j]=blocked/len(selected)
    fig,ax=plt.subplots(figsize=(7.6,3.9),layout="constrained")
    ax.imshow(values,cmap="GnBu",vmin=0,vmax=1,aspect="auto")
    ax.set(xticks=range(3),xticklabels=LABELS,yticks=range(6),yticklabels=categories,xlabel="Assessment mode")
    for (i,j),value in np.ndenumerate(values):
        blocked,total=counts[i,j]
        ax.text(j,i,f"{blocked}/{total}",ha="center",va="center",color="white" if value>.7 else NAVY,fontweight="bold")
    save(fig,"figure_04_fault_categories")


def timing():
    rows=SUMMARY["timing"]
    x=np.arange(len(rows))
    fig,ax=plt.subplots(figsize=(8,4.3),layout="constrained")
    for field,label,color,offset in [("parse_ms","JSON parsing",GRAY,-.04),("evaluate_ms","Rule evaluation",TEAL,0),
                                    ("parse_and_evaluate_ms","Parse + evaluate",ORANGE,.04)]:
        center=np.array([r[field+"_median"] for r in rows])
        low=np.array([r[field+"_q1"] for r in rows]);high=np.array([r[field+"_q3"] for r in rows])
        ax.errorbar(x+offset,center,yerr=[center-low,high-center],label=label,marker="o",capsize=4,color=color,linewidth=1.7)
    ax.set(xticks=x,xticklabels=[f"{r['records_each']:,}\n{r['input_bytes']/1024:.1f} KiB" for r in rows],
           yscale="log",ylabel="Time (ms, logarithmic scale)",xlabel="SBOM components and scan findings (each); serialized input size")
    ax.grid(axis="y",which="both",alpha=.16);ax.legend(frameon=False,loc="upper left")
    save(fig,"figure_05_processing_time")


def tests():
    unit=SUMMARY["unit_tests"]["groups"]
    browser=json.loads((ROOT/"results"/"browser_tests.json").read_text())
    labels=["Core and reports","Trivy adapter contracts","CLI integration","Dashboard HTTP","Browser scenarios"]
    counts=[unit["CoreTests"],unit["TrivyTests"],unit["CommandTests"],unit["DashboardTests"],browser["passed"]]
    fig,ax=plt.subplots(figsize=(7.6,3.1),layout="constrained")
    y=np.arange(len(labels));ax.barh(y,counts,color=[TEAL]*4+[NAVY],height=.56)
    ax.set(yticks=y,yticklabels=labels,xlim=(0,22),xlabel="Executed tests / scenarios (all passed)",xticks=[0,5,10,15,20]);ax.invert_yaxis()
    ax.xaxis.grid(True,alpha=.2);ax.set_axisbelow(True)
    for i,value in enumerate(counts):ax.text(value+.3,i,str(value),va="center",fontweight="bold")
    save(fig,"figure_06_test_outcomes")


if __name__ == "__main__":
    architecture();detection();confusion();category_heatmap();timing();tests()
    print("Generated six figures in PNG, SVG, and PDF from saved measurements.")
