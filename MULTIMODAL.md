# Multimodal companion implementation

`multimodal_app.py` coordinates three pre-trained model families in a reviewed incident case:

| Domain | Pre-trained model | Role |
|---|---|---|
| Image | EasyOCR CRAFT detector and english_g2 recogniser | Extract SSH log screenshot text |
| Audio | Whisper base.en via faster-whisper | Transcribe spoken analyst handover notes |
| Text | Existing local Llama 3 via Ollama | Rephrase the parsed evidence summary |

The rules and self-trained Isolation Forest are **not** counted as pre-trained models.
The original `app.py` dashboard and 80-scenario detector benchmark are unchanged.
The three-domain workflow addresses the template's model/domain requirement; academic acceptance remains the module team's decision.

## Run locally

```powershell
.venv\Scripts\python.exe -m pip install -r requirements-multimodal.txt
.venv\Scripts\python.exe prepare_multimodal_models.py
# Ollama must be installed and serving llama3:latest locally.
.venv\Scripts\python.exe -m streamlit run multimodal_app.py
```

Weights download only through the explicit preparation command. They are ignored by Git;
the report does not require redistributing third-party model weights. Record hashes and
runtime versions with `record_multimodal_environment.py`. EasyOCR and faster-whisper
are pinned in the optional requirements; full observed model/runtime identities are in
`evaluation_results/multimodal/environment.json`.

## Safety and provenance

- Extraction is a draft. Review/correct the text, then confirm before case analysis.
- OCR boxes, confidence values, original text, corrected text and file hashes are retained.
- Box geometry reconstructs fragmented lines; characters/IPs are never silently repaired.
- Transcript text is an **unverified note**, excluded from the LLM's factual prompt and from rule severity.
- LLM lexical validation is not a semantic guarantee; accepted text can still overstate certainty.
- Timeouts and rejected output retain the deterministic summary. No blocking or remediation is executed.
- Upload limits: 20 MiB; images 16 megapixels; audio 120 seconds. Use short trusted inputs.
- Model inference is local after setup. JSON case exports may contain sensitive logs/notes; handle accordingly.

## Executed checks and limits

The expanded suite contains **99 passing tests** (83 existing + 15 multimodal
contract tests + one unfitted-model comparison regression). An unfitted model
preserves rule results with `insufficient_training_data` and null anomaly values.
Fifteen curated log fixtures have a separate validation command, not an inflated Pytest count.

```powershell
.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
.venv\Scripts\python.exe validate_test_logs.py
.venv\Scripts\python.exe evaluate_multimodal.py --prepare-images
powershell -NoProfile -File prepare_synthetic_audio.ps1
.venv\Scripts\python.exe evaluate_multimodal.py
```

The live smoke benchmark consists of six rendered screenshots (three source scenarios,
each clear and Gaussian-blurred), three Windows-synthesised speech notes and three LLM calls.
These are development fixtures, **not independent held-out observations or a user study**.
The synthetic voice must never be used as the student's required video narration.

Results are exported to `evaluation_results/multimodal/results.json`. The initial
fragment-per-line OCR result is preserved in `initial_fragment_results.json`.
Geometric reconstruction improved uncorrected downstream class agreement from 1/6 to 3/6;
three cases still failed. Low character error does not imply correct security conclusions.
Speech word error rates were 0, 0 and 0.1176 after lowercase/alphanumeric tokenisation.
The LLM validator accepted 1/3 outputs and rejected 2/3; this is an acceptance rate, not accuracy.

Required follow-up: real human recordings with consent, more fonts/resolutions and
independent screenshots, claim-level LLM assessment, human-review effort measurement,
and comparison against text-only input. The companion UI has not established that
multimodal input improves analyst outcomes.
