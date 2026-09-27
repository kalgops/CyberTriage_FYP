# CyberTriage Final Project

**AI-Assisted Cybersecurity Log Triage and Incident Explanation System**
CM3070 Final Year Project - Evidence-based triage and multimodal case review

This repository contains the final implementation submitted for the CM3070
Final Year Project. It preserves the evidence-first SSH triage pipeline and the
evaluated comparison between transparent rules and Isolation Forest.

## Pre-trained multimodal extension

The companion `multimodal_app.py` coordinates **EasyOCR (image)**,
**Whisper base.en (audio)** and **Llama 3 (text)** in a reviewed incident case.
The rule detector and self-trained Isolation Forest are not counted as pre-trained models.
See [MULTIMODAL.md](MULTIMODAL.md) for installation, operation, model provenance,
executed smoke-test results and limitations. The original dashboard remains `app.py`.

The expanded suite passes **100 tests**. Any 83-test result below refers to the
earlier baseline run, not the current suite. The 80-scenario detector benchmark
is unchanged; the new multimodal smoke evaluation is a separate development experiment.

## Prototype purpose

This prototype demonstrates the feasibility of the final project by showing that
raw SSH authentication logs can be **parsed, analysed, classified, and converted
into an understandable incident triage report**.

It focuses on one core feature: detecting and explaining **SSH brute-force
activity**. Given raw `sshd` log text, the system:

1. Parses each line into structured fields (timestamp, event type, username,
   source IP, port).
2. Groups failed logins by source IP and applies deterministic threshold rules.
3. Classifies the incident into a clear category.
4. Generates a plain-English triage report grounded only in the parsed evidence.
5. Aggregates six per-IP behavioural features and compares the rule result with
   a reproducible Isolation Forest baseline.

> **This is a defensive cybersecurity education prototype only.** It uses
> **synthetic sample logs only** and contains no offensive capability - no
> scanning, exploitation, password guessing, or attack automation.

## Project structure

```
CyberTriage_FYP/
├── app.py                 # Streamlit dashboard
├── multimodal_app.py      # Image/audio/text case-review companion
├── MULTIMODAL.md           # Model setup, provenance and evaluation limitations
├── requirements-multimodal.txt
├── prepare_multimodal_models.py
├── evaluate_multimodal.py  # Live synthetic OCR/ASR/LLM smoke benchmark
├── multimodal_fixtures/    # Rendered screenshots and labelled synthetic audio
├── README.md
├── requirements.txt
├── pytest.ini
├── evaluate_models.py     # Reproducible model comparison and CSV metrics
├── generate_report_figures.py
├── evaluation_results/    # Scenario results, metrics and report figures
├── test_logs/             # 15 curated synthetic fixtures and expected outcomes
├── validate_test_logs.py  # Separate fixture checker
├── cybertriage/
│   ├── __init__.py
│   ├── parser.py          # SSH log parsing -> Pandas DataFrame
│   ├── detector.py        # Brute-force detection + severity thresholds
│   ├── classifier.py      # Deterministic incident classification
│   ├── report.py          # Template report (+ optional Ollama explanation)
│   ├── anomaly.py         # Six-feature aggregation and Isolation Forest
│   ├── multimodal.py      # Pre-trained adapters, review gate and case provenance
│   ├── synthetic_dataset.py # Fixed-seed labelled evaluation scenarios
│   ├── config.py          # Configuration and validation
│   ├── batch.py           # Batch processing utilities
│   ├── export.py          # Structured result exports
│   ├── performance.py     # Performance measurement utilities
│   ├── pdf_generator.py   # PDF incident reports
│   ├── advanced_viz.py    # Analytical visualisations
│   └── sample_data.py     # Loads bundled synthetic samples
├── sample_logs/
│   ├── normal_auth.log
│   ├── brute_force_auth.log
│   └── mixed_auth.log
└── tests/
    ├── test_parser.py
    ├── test_detector.py
    ├── test_classifier.py
    ├── test_anomaly.py
    ├── test_dataset.py
    ├── test_config.py
    ├── test_export.py
    ├── test_pdf_generator.py
    ├── test_performance.py
    ├── test_multimodal.py
    └── test_report.py
```

## Install dependencies

```bash
pip install -r requirements.txt
```

Python 3.11+ is recommended.

## Run the Streamlit app

```bash
streamlit run app.py
```

Then in the dashboard you can:

- Paste SSH log text, **or** upload a `.log` / `.txt` file, **or** click one of
  the **Load sample** buttons.
- Click **Analyse** to see the incident type, severity, metrics, evidence
  tables, plain-English explanation, and recommended next steps.

## Run the tests

```bash
pytest
```

The current suite contains 100 tests (83 original, 15 multimodal contracts,
one unfitted-model comparison regression and one real PDF-export regression) covering the original pipeline,
threshold boundaries, out-of-order timestamps, IPv6, public-key authentication,
large input, feature aggregation, insufficient model training, deterministic
model output, dataset labelling, and rejection of invented IP addresses, counts,
and unsupported compromise claims in optional LLM text.

## Run the comparative evaluation

```bash
python evaluate_models.py --output-dir evaluation_results
```

The command uses seed `3070` to generate 80 labelled scenarios across eight
categories. Twenty-four normal observations are used to fit the Isolation
Forest; 56 scenarios are held out. It writes:

- `scenario_results.csv` - per-scenario features and predictions
- `model_metrics.csv` - precision, recall, F1 and false-positive rate
- `per_category_results.csv` - category-level coverage
- `model_comparison.png` - report-ready comparison graph

The synthetic labels are defined by scenario construction. Metrics demonstrate
controlled behaviour only and must not be presented as production accuracy.

## Implemented feature vector

Each source IP is represented by failed count, successful count, unique
usernames, events per minute, observed duration, and failure ratio. The
Isolation Forest uses 200 trees, contamination `0.1`, and random seed `3070`.
It refuses to fit with fewer than 20 normal observations and never replaces the
transparent threshold result in the interface.

The tests cover parsing (IP, username, failed/successful detection), detection
(brute-force flagged, normal not flagged as high, time window, escalation), and
classification (correct incident type per sample).

## Sample logs

| File | Description | Expected result |
|------|-------------|-----------------|
| `normal_auth.log` | A few successful logins plus one or two isolated failed logins from different IPs. | Normal Activity (low risk). |
| `brute_force_auth.log` | 18 failed attempts in the bundled sample from a single IP (`192.168.1.45`) against seven usernames. | Possible SSH Brute Force Attempt - **High** severity. |
| `mixed_auth.log` | Normal logins, one clearly suspicious IP (`172.16.0.99`) with repeated failures, plus unrelated isolated failures. | Suspicious IP identified clearly. |

All samples use **synthetic private IP ranges** (`192.168.x.x`, `10.x.x.x`,
`172.16.x.x`).

## Detection thresholds

Failed attempts per source IP:

- **Low:** 3-4 failed attempts
- **Medium:** 5-9 failed attempts
- **High:** 10+ failed attempts

Severity is **escalated by one level** when the same IP targets multiple
usernames (consistent with brute-force / spraying behaviour).

## Incident categories

The classifier is deterministic and evidence-based, returning one of:

- `Possible SSH Brute Force Attempt`
- `Suspicious Login Pattern`
- `Normal Activity`
- `Parsing Error / Insufficient Evidence`

## Using Ollama locally

The report explanation works fully **without any LLM** because it has a
**template-based fallback**. Detection and classification are always
deterministic; the local LLM is only ever used to *rephrase* the already-computed
summary. It is given only parsed evidence with an instruction not to invent
unsupported facts, and its response is checked against the evidence before it
is displayed. New IP addresses, new numeric values, excessive output, and
unsupported high-risk claims trigger the deterministic fallback. If Ollama is
not reachable (closed, model missing, or the API call fails), the app also falls
back to the template generator and clearly labels the explanation source.

If you do want richer explanations, install [Ollama](https://ollama.com) and:

- **Check installed models:**
  ```bash
  ollama list
  ```
- **Run a model manually (also downloads it if needed):**
  ```bash
  ollama run llama3
  ```
- **Use a different model:** set the `OLLAMA_MODEL` environment variable, or
  type the model name directly into the **Ollama model** box in the Streamlit
  sidebar.
- **Default host:** `http://localhost:11434` (override with `OLLAMA_HOST` or the
  **Ollama host** box in the sidebar).

### Configuration

| Setting | Environment variable | Default | Sidebar control |
|---------|----------------------|---------|-----------------|
| Model | `OLLAMA_MODEL` | `llama3` | "Ollama model" |
| Host | `OLLAMA_HOST` | `http://localhost:11434` | "Ollama host" |

Sidebar values take effect immediately and override the environment defaults,
so you can change the model or host without editing any code.

### Example (Windows PowerShell)

```powershell
$env:OLLAMA_MODEL="llama3"
$env:OLLAMA_HOST="http://localhost:11434"
python -m streamlit run app.py
```

In the dashboard, tick **"Use local Ollama explanation"**. A status line shows
**"Ollama available"** or **"Ollama unavailable - template fallback will be
used"**. The explanation panel is always labelled with its source: *Generated by
local Ollama LLM*, *Template fallback used...*, or *Template-based explanation*.

## Mapping to the final year project report (Chapter 4)

This prototype directly supports **Chapter 4 (Implementation / Prototype)** of
the report:

- **4.x Log ingestion & parsing** - `cybertriage/parser.py` shows that
  heterogeneous SSH log lines can be reliably normalised into structured data.
- **4.x Detection engine** - `cybertriage/detector.py` demonstrates the
  evidence-based threshold and escalation rules used to flag brute-force IPs.
- **4.x Incident classification** - `cybertriage/classifier.py` provides the
  deterministic decision logic mapping evidence to incident categories.
- **4.x Explanation generation** - `cybertriage/report.py` shows the
  template-grounded explanation approach (and the optional LLM augmentation
  path), evidencing the "incident explanation" aim of the project.
- **4.x User interface** - `app.py` provides the analyst-facing dashboard,
  evidencing usability for a junior analyst / student.
- **4.x Evaluation & testing** - the `tests/` suite demonstrates correctness of
  the parsing, detection, and classification components.

Together these establish **feasibility**: raw logs in, a clear, justified,
human-readable incident report out.
