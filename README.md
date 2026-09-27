# CyberTriage Final Project

**AI-Assisted Cybersecurity Log Triage and Incident Explanation System**
CM3070 Final Year Project - Rule and Isolation Forest Comparison

This repository contains the final implementation submitted for the CM3070
Final Year Project. It preserves the evidence-first SSH triage pipeline and the
evaluated comparison between transparent rules and Isolation Forest.

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
cybertriage_prototype/
├── app.py                 # Streamlit dashboard
├── README.md
├── requirements.txt
├── pytest.ini
├── cybertriage/
│   ├── __init__.py
│   ├── parser.py          # SSH log parsing -> Pandas DataFrame
│   ├── detector.py        # Brute-force detection + severity thresholds
│   ├── classifier.py      # Deterministic incident classification
│   ├── report.py          # Template report (+ optional Ollama explanation)
│   └── sample_data.py     # Loads bundled synthetic samples
├── sample_logs/
│   ├── normal_auth.log
│   ├── brute_force_auth.log
│   └── mixed_auth.log
└── tests/
    ├── test_parser.py
    ├── test_detector.py
    └── test_classifier.py
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

The expanded suite contains 83 tests covering the original pipeline,
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
| `brute_force_auth.log` | 15+ failed attempts from a single IP (`192.168.1.45`) against many usernames (`root`, `admin`, `test`, `ubuntu`, ...). | Possible SSH Brute Force Attempt - **High** severity. |
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
