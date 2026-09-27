"""Live OCR/ASR/LLM smoke evaluation. Not a real-user or field benchmark.

Run --prepare-images, then prepare_synthetic_audio.ps1, then run without flags.
All generated speech is explicitly synthetic test input, NOT submission narration.
"""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import re
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from cybertriage import multimodal as mm

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "multimodal_fixtures"
RESULTS = ROOT / "evaluation_results" / "multimodal"

def distance(a, b):
    row = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        next_row = [i]
        for j, y in enumerate(b, 1):
            next_row.append(min(next_row[-1] + 1, row[j] + 1, row[j-1] + (x != y)))
        row = next_row
    return row[-1]

def normalized_words(text):
    return re.findall(r"[a-z0-9]+", text.lower())

def prepare_images():
    FIXTURES.mkdir(exist_ok=True)
    font = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 22)
    for name in ["01_normal_login", "05_high_threshold_10_failures", "12_ipv6_authentication"]:
        text = (ROOT / "test_logs" / f"{name}.log").read_text().strip()
        lines = text.splitlines()
        width = int(max(font.getlength(line) for line in lines)) + 40
        image = Image.new("RGB", (width, len(lines)*32+40), "white")
        draw = ImageDraw.Draw(image)
        for i, line in enumerate(lines):
            draw.text((20,20+i*32), line, fill="black", font=font)
        image.save(FIXTURES / f"{name}_clean.png")
        image.filter(ImageFilter.GaussianBlur(1.0)).save(FIXTURES / f"{name}_blur.png")
    print("Prepared six synthetic log screenshots.")

def evaluate():
    RESULTS.mkdir(parents=True, exist_ok=True)
    results = {"scope": "Synthetic smoke benchmark: rendered logs and Windows TTS notes; no user study.",
               "ocr": [], "asr": [], "llm": []}
    for path in sorted(FIXTURES.glob("*.png")):
        stem = path.stem.rsplit("_",1)[0]
        expected = (ROOT / "test_logs" / f"{stem}.log").read_text().strip()
        extraction = mm.extract_image(path.read_bytes())
        truth = mm.build_case(expected, reviewed=True)
        predicted = mm.build_case(extraction.text, reviewed=True) if extraction.text.strip() else None
        result = asdict(extraction)
        result.update(file=path.name, reference=expected,
                      character_error_rate=distance(expected, extraction.text)/max(1,len(expected)),
                      uncorrected_class_matches=bool(predicted and predicted["report"]["incident_type"] == truth["report"]["incident_type"]),
                      uncorrected_failed_count=predicted["detection"]["total_failed"] if predicted else 0,
                      reference_failed_count=truth["detection"]["total_failed"])
        results["ocr"].append(result)
        print(path.name, result["character_error_rate"], result["uncorrected_class_matches"], flush=True)
    for path in sorted(FIXTURES.glob("*.wav")):
        reference = path.with_suffix(".txt").read_text().strip()
        extraction = mm.extract_audio(path.read_bytes())
        truth = normalized_words(reference)
        result = asdict(extraction)
        result.update(file=path.name, reference=reference,
                      word_error_rate=distance(truth,normalized_words(extraction.text))/max(1,len(truth)),
                      synthetic_voice=True)
        results["asr"].append(result)
        print(path.name, result["word_error_rate"], flush=True)
    for name in ["01_normal_login", "03_low_threshold_3_failures", "05_high_threshold_10_failures"]:
        case = mm.build_case((ROOT / "test_logs" / f"{name}.log").read_text(), reviewed=True)
        result = mm.explain_case(case)
        result["fixture"] = name
        results["llm"].append(result)
        print(name, result["status"], flush=True)
    (RESULTS / "results.json").write_text(json.dumps(results,indent=2), encoding="utf-8")
    print("Saved", RESULTS / "results.json")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare-images", action="store_true")
    args = parser.parse_args()
    prepare_images() if args.prepare_images else evaluate()
