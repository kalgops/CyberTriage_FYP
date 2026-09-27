"""Generate implementation-specific report figures without external services."""

from __future__ import annotations

import csv
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "evaluation_results"
OUT.mkdir(exist_ok=True)

NAVY = "#153D5C"
BLUE = "#2E75B6"
GREEN = "#4C956C"
ORANGE = "#E78A37"
RED = "#C84C4C"
LIGHT = "#F4F7FA"
MID = "#D8E4ED"
DARK = "#20303C"
GREY = "#667784"
WHITE = "#FFFFFF"


def font(size: int, bold: bool = False):
    candidates = [
        Path("C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf"),
        Path("C:/Windows/Fonts/calibrib.ttf" if bold else "C:/Windows/Fonts/calibri.ttf"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def centered(draw, box, text, fnt, fill=DARK, spacing=5):
    x1, y1, x2, y2 = box
    bounds = draw.multiline_textbbox((0, 0), text, font=fnt, align="center", spacing=spacing)
    w, h = bounds[2] - bounds[0], bounds[3] - bounds[1]
    draw.multiline_text(((x1+x2-w)/2, (y1+y2-h)/2), text, font=fnt, fill=fill, align="center", spacing=spacing)


def rounded(draw, box, fill, outline=BLUE, radius=14, width=3):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def arrow(draw, start, end, fill=GREY, width=5):
    draw.line([start, end], fill=fill, width=width)
    x, y = end
    draw.polygon([(x, y), (x-14, y-9), (x-14, y+9)], fill=fill)


def architecture():
    im = Image.new("RGB", (1800, 920), WHITE)
    d = ImageDraw.Draw(im)
    d.text((60, 35), "Implemented CyberTriage Architecture", font=font(44, True), fill=NAVY)
    d.text((60, 92), "Evidence provenance is preserved; machine learning supplements rather than replaces transparent rules.", font=font(24), fill=GREY)

    boxes = [
        (60, 250, 280, 405, "SSH log\ninput", LIGHT, BLUE),
        (350, 250, 570, 405, "Validated parser\nIPv4/IPv6\npassword/public key", LIGHT, BLUE),
        (640, 250, 860, 405, "Per-IP feature\naggregation\n6 features", LIGHT, BLUE),
    ]
    for x1,y1,x2,y2,label,fill,outline in boxes:
        rounded(d,(x1,y1,x2,y2),fill,outline); centered(d,(x1,y1,x2,y2),label,font(23,True))
    arrow(d,(280,328),(350,328)); arrow(d,(570,328),(640,328))

    rounded(d,(950,155,1200,300),"#EDF7F0",GREEN); centered(d,(950,155,1200,300),"Threshold baseline\ninterpretable rules",font(23,True))
    rounded(d,(950,365,1200,510),"#FFF3E8",ORANGE); centered(d,(950,365,1200,510),"Isolation Forest\n200 trees\nscore + prediction",font(23,True))
    d.line([(860,328),(900,328),(900,228),(950,228)],fill=GREY,width=5)
    d.line([(900,328),(900,438),(950,438)],fill=GREY,width=5)
    arrow(d,(1200,228),(1290,300)); arrow(d,(1200,438),(1290,365))

    rounded(d,(1290,245,1510,420),MID,NAVY); centered(d,(1290,245,1510,420),"Side-by-side\ncomparison\nrule remains\nauthoritative",font(22,True))
    arrow(d,(1510,332),(1580,332))
    rounded(d,(1580,245,1750,420),LIGHT,BLUE); centered(d,(1580,245,1750,420),"Deterministic\nclassification",font(22,True))

    arrow(d,(1665,420),(1665,550))
    rounded(d,(1450,550,1750,710),"#EDF7F0",GREEN); centered(d,(1450,550,1750,710),"Evidence-grounded report\nIP, counts, users, interval\nrecommended checks",font(22,True))
    arrow(d,(1450,630),(1320,630))
    rounded(d,(1010,550,1320,710),"#FFF3E8",ORANGE); centered(d,(1010,550,1320,710),"Optional local LLM\nrephrasing only\nexplicit provenance + fallback",font(21,True))

    d.text((70, 785), "Legend", font=font(24,True), fill=NAVY)
    for x, color, label in [(190,BLUE,"implemented data processing"),(610,GREEN,"deterministic/grounded control"),(1050,ORANGE,"probabilistic optional component")]:
        d.rounded_rectangle((x,780,x+48,828),radius=8,fill=color)
        d.text((x+62,787),label,font=font(21),fill=DARK)
    im.save(OUT / "implemented_architecture.png", quality=95)


def assurance():
    im = Image.new("RGB", (1800, 900), WHITE)
    d = ImageDraw.Draw(im)
    d.text((60, 35), "Readability Is Not the Same as Explainability", font=font(43,True), fill=NAVY)
    d.text((60, 93), "The report separates evidence provenance, decision transparency and natural-language presentation.", font=font(24), fill=GREY)

    cols = [
        (80,190,540,690,"1. Evidence provenance",BLUE,
         "Raw log lines retained\nParsed fields visible\nCounts recomputable\nNo unsupported event becomes evidence"),
        (670,190,1130,690,"2. Decision explanation",GREEN,
         "Threshold conditions explicit\nSix anomaly features visible\nAnomaly score reported\nModel disagreement preserved"),
        (1260,190,1720,690,"3. Human readability",ORANGE,
         "Template summary is deterministic\nLLM may only rephrase evidence\nGeneration source is labelled\nFallback on failure or empty output"),
    ]
    for x1,y1,x2,y2,title,color,body in cols:
        rounded(d,(x1,y1,x2,y2),LIGHT,color,radius=22,width=5)
        d.rounded_rectangle((x1,y1,x2,y1+105),radius=22,fill=color)
        centered(d,(x1+15,y1+10,x2-15,y1+95),title,font(27,True),WHITE)
        centered(d,(x1+35,y1+130,x2-35,y2-35),body,font(24),DARK,spacing=16)
    arrow(d,(540,440),(670,440),GREY,6); arrow(d,(1130,440),(1260,440),GREY,6)
    d.rounded_rectangle((290,760,1510,835),radius=18,fill="#FCEAEA",outline=RED,width=3)
    centered(d,(290,760,1510,835),"Safety conclusion: fluent wording is not accepted as proof; claims must remain traceable to extracted evidence.",font(25,True),RED)
    im.save(OUT / "explanation_assurance.png", quality=95)


def category_diagnostics():
    rows = []
    with (OUT / "per_category_results.csv").open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    im = Image.new("RGB", (1800, 1000), WHITE)
    d = ImageDraw.Draw(im)
    d.text((60, 35), "Correct Decisions by Scenario Category", font=font(43,True), fill=NAVY)
    d.text((60, 92), "Counts on the held-out partition; category sizes are shown beside labels.", font=font(24), fill=GREY)
    left, top, right, bottom = 520, 170, 1700, 875
    d.line((left,top,left,bottom),fill=DARK,width=3); d.line((left,bottom,right,bottom),fill=DARK,width=3)
    for tick in range(0,11,2):
        x=left+(right-left)*tick/10
        d.line((x,top,x,bottom),fill="#E5EBF0",width=2)
        d.text((x-10,bottom+15),str(tick),font=font(19),fill=GREY)
    bar_h=27; group_h=82
    for i,row in enumerate(rows):
        y=top+25+i*group_h
        label=row["category"].replace("_"," ")
        n=int(row["scenarios"])
        d.text((60,y+8),f"{label} (n={n})",font=font(21),fill=DARK)
        rule=int(row["threshold_correct"]); iso=int(row["isolation_forest_correct"])
        d.rectangle((left,y,right if rule==10 else left+(right-left)*rule/10,y+bar_h),fill=BLUE)
        d.rectangle((left,y+bar_h+8,left+(right-left)*iso/10,y+2*bar_h+8),fill=ORANGE)
        d.text((left+(right-left)*rule/10+8,y+2),str(rule),font=font(19,True),fill=BLUE)
        d.text((left+(right-left)*iso/10+8,y+bar_h+10),str(iso),font=font(19,True),fill=ORANGE)
    d.rectangle((680,920,715,955),fill=BLUE); d.text((730,925),"threshold baseline",font=font(21),fill=DARK)
    d.rectangle((1050,920,1085,955),fill=ORANGE); d.text((1100,925),"Isolation Forest",font=font(21),fill=DARK)
    im.save(OUT / "per_category_diagnostics.png", quality=95)


if __name__ == "__main__":
    architecture(); assurance(); category_diagnostics()
    print("Generated:", *(p.name for p in sorted(OUT.glob("*.png"))), sep="\n- ")
