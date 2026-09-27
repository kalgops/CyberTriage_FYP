# CyberTriage - AI-Assisted Security Analytics Platform

[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-63%20passed-success)](tests/)

**AI-Assisted Cybersecurity Log Triage and Incident Explanation System**

🎓 **CM3070 Final Year Project** | University of London | August 2026

---

## 🎯 Project Overview

CyberTriage is an advanced security analytics platform that transforms raw SSH authentication logs into actionable intelligence. By orchestrating rule-based detection, machine learning anomaly detection, and optional LLM explanation generation, the system provides comprehensive threat analysis while maintaining complete evidence provenance.

### **Key Innovation**
Unlike black-box security tools, CyberTriage preserves complete evidence traceability from raw log line to final report, ensuring that AI-generated explanations remain subordinate to and validated against parsed evidence.

---

## ✨ Features

### **Core Capabilities**
- 🔍 **Intelligent Log Parsing**: Supports IPv4/IPv6, password/publickey authentication
- 🎯 **Dual Detection**: Rule-based thresholds + Isolation Forest ML
- 🤖 **AI Orchestration**: Multiple models working together with disagreement preservation
- 📊 **11 Interactive Visualizations**: Gauges, timelines, heatmaps, radar charts
- 📑 **Professional PDF Reports**: Enterprise-ready documentation
- 🛡️ **LLM Safety**: Validates AI output against evidence (no invented facts)
- ✅ **63 Automated Tests**: Comprehensive quality assurance

### **Advanced Analytics**
- **Attack Pattern Radar**: 5-dimensional threat profiling
- **Threat Heatmap**: Activity patterns by time and IP
- **Feature Importance**: ML model transparency
- **Model Comparison**: Side-by-side rule vs. ML results
- **Time Series Analysis**: Event frequency visualization
- **IP Reputation Scoring**: Color-coded threat levels

---

## 🚀 Quick Start

### **Prerequisites**
- Python 3.11+ (3.13 recommended)
- pip package manager

### **Installation**

```bash
# Clone the repository
git clone https://github.com/yourusername/cybertriage.git
cd cybertriage

# Install dependencies
pip install -r requirements.txt

# Run the application
python -m streamlit run app.py
```

The dashboard will open at `http://localhost:8501`

### **Optional: Ollama Integration**

For AI-generated explanations (optional):

```bash
# Install Ollama
# Visit: https://ollama.com

# Download a model
ollama pull llama3

# Enable in dashboard sidebar
# Check "Enable Ollama LLM"
```

---

## 📊 Usage

### **1. Load Sample Data**
Click one of the sample buttons:
- 🟢 **Normal Activity**: Legitimate logins
- 🔴 **Brute Force Attack**: 18 failed attempts
- 🟡 **Mixed Activity**: Normal + suspicious IP

### **2. Or Upload Your Own**
- Upload `.log` or `.txt` file
- Or paste SSH logs directly

### **3. Analyze**
Click "🔍 Analyze Logs" to see:
- Incident classification and severity
- Evidence-based metrics
- Interactive visualizations
- Model comparison (Rule vs. ML)
- Recommended actions

### **4. Export**
Download results in three formats:
- 📄 **Text Report**: Quick sharing
- 📊 **CSV Data**: Further analysis
- 📑 **PDF Report**: Professional documentation

---

## 🏗️ Architecture

```
Raw Logs
    ↓
Parser (regex + validation)
    ↓
Structured DataFrame
    ↓
    ├─→ Rule Detector (thresholds)
    └─→ Feature Aggregator → Isolation Forest
                ↓
        Model Comparison
                ↓
        Classifier (deterministic)
                ↓
        Report Builder (template + optional LLM)
                ↓
        Dashboard (Streamlit + Plotly)
```

### **Key Components**

| Module | Purpose | Lines of Code |
|--------|---------|---------------|
| `parser.py` | SSH log parsing | 165 |
| `detector.py` | Rule-based detection | 163 |
| `classifier.py` | Incident classification | 52 |
| `anomaly.py` | ML feature aggregation | 123 |
| `report.py` | Report generation | 344 |
| `advanced_viz.py` | Visualizations | 399 |
| `pdf_generator.py` | PDF export | 280 |
| `app.py` | Web dashboard | 900+ |

---

## 🧪 Testing

### **Run All Tests**
```bash
pytest
```

### **Test Coverage**
- ✅ **Parser**: 12 tests (IP extraction, event types, IPv6, edge cases)
- ✅ **Detector**: 18 tests (thresholds, escalation, time windows)
- ✅ **Classifier**: 6 tests (all incident categories)
- ✅ **Report**: 15 tests (template, LLM validation, safety)
- ✅ **Anomaly**: 8 tests (features, model training, refusal)
- ✅ **Dataset**: 4 tests (scenario generation)

**Total**: 63 tests, 100% pass rate ✅

### **Run Evaluation**
```bash
python evaluate_models.py --output-dir evaluation_results
```

Generates:
- `model_metrics.csv`: Precision, recall, F1, FPR
- `scenario_results.csv`: Per-scenario predictions
- `per_category_results.csv`: Category-level accuracy
- `model_comparison.png`: Visualization

---

## 📈 Evaluation Results

### **Synthetic Dataset**
- **80 scenarios** across 8 categories
- **24 normal** (training), **56 held-out** (test)
- **Seed 3070** for reproducibility

### **Model Performance**

| Model | Precision | Recall | F1 | FPR |
|-------|-----------|--------|-----|-----|
| **Threshold Baseline** | 1.00 | 1.00 | 1.00 | 0.00 |
| **Isolation Forest** | 0.86 | 0.15 | 0.26 | 0.06 |

**Interpretation**: Rule-based detector achieves perfect performance on synthetic data. Isolation Forest is conservative (high precision, low recall) - acceptable as a supplementary model.

---

## 🎓 Academic Context

### **Project Template**
CM3020 Artificial Intelligence - **Project Idea 1**: Orchestrating AI models to achieve a goal

### **Research Questions**
1. How can raw authentication logs be reliably normalized into behavioral features?
2. How can transparent rules and unsupervised anomaly detection be effectively combined?
3. How can AI-generated explanations remain grounded in parsed evidence?
4. How effectively does the system detect and explain SSH brute-force patterns?

### **Novel Contributions**
1. **Evidence Validation Framework**: Validates LLM output against parsed facts
2. **Side-by-Side Comparison**: Preserves model disagreement
3. **Graduated Explainability**: Separates provenance, transparency, and readability
4. **Defensive Design**: Works without LLM, refuses unsafe predictions

---

## 📚 Documentation

- **[DOCUMENTATION.md](DOCUMENTATION.md)**: Complete project documentation (10,000+ words)
- **[VIDEO_SCRIPT.md](VIDEO_SCRIPT.md)**: Demonstration video script
- **[README.md](README.md)**: This file
- **[requirements.txt](requirements.txt)**: Python dependencies
- **[pytest.ini](pytest.ini)**: Test configuration

---

## 🛠️ Technology Stack

### **Core**
- **Python 3.13**: Modern language features
- **Streamlit 1.62**: Web dashboard
- **Pandas 2.3**: Data manipulation
- **Scikit-learn 1.7**: Machine learning
- **Plotly 7.0**: Interactive visualizations

### **Additional**
- **FPDF2 2.8**: PDF generation
- **ReportLab 5.0**: PDF formatting
- **Pytest 8.4**: Testing framework
- **Matplotlib 3.10**: Static plots
- **Seaborn 0.13**: Statistical visualizations

---

## 📂 Project Structure

```
cybertriage/
├── app.py                      # Main Streamlit dashboard
├── requirements.txt            # Python dependencies
├── pytest.ini                  # Test configuration
├── README.md                   # This file
├── DOCUMENTATION.md            # Complete documentation
├── VIDEO_SCRIPT.md             # Demo video script
├── cybertriage/                # Core package
│   ├── __init__.py
│   ├── parser.py               # Log parsing
│   ├── detector.py             # Rule-based detection
│   ├── classifier.py           # Incident classification
│   ├── anomaly.py              # ML feature aggregation
│   ├── report.py               # Report generation
│   ├── advanced_viz.py         # Visualizations
│   ├── pdf_generator.py        # PDF export
│   ├── sample_data.py          # Sample logs
│   └── synthetic_dataset.py    # Evaluation dataset
├── sample_logs/                # Bundled samples
│   ├── normal_auth.log
│   ├── brute_force_auth.log
│   └── mixed_auth.log
├── tests/                      # Test suite
│   ├── test_parser.py
│   ├── test_detector.py
│   ├── test_classifier.py
│   ├── test_report.py
│   ├── test_anomaly.py
│   └── test_dataset.py
└── evaluation_results/         # Evaluation outputs
    ├── model_metrics.csv
    ├── scenario_results.csv
    ├── per_category_results.csv
    └── model_comparison.png
```

---

## 🎯 Detection Thresholds

| Severity | Failed Attempts | Behavior |
|----------|----------------|----------|
| **Low** | 3-4 | Single username |
| **Medium** | 5-9 OR 3-4 with multiple users | Possible spraying |
| **High** | 10+ OR 5-9 with multiple users | Clear brute-force |

**Escalation Rule**: Severity increases by one level when multiple usernames are targeted (indicates password spraying).

---

## 🔒 Security & Privacy

### **Defensive Design**
- ✅ **Local processing**: No cloud dependencies
- ✅ **Synthetic samples**: No real credentials
- ✅ **No offensive capabilities**: Education-only
- ✅ **LLM validation**: Prevents invented facts
- ✅ **Explicit provenance**: Labels explanation source

### **Safety Checks**
1. Parser validates IP addresses (rejects invalid)
2. Model refuses prediction with <20 training samples
3. LLM output checked for invented IPs, counts, claims
4. Automatic fallback to deterministic template
5. All evidence traceable to source logs

---

## 🤝 Contributing

This is an academic project submitted for CM3070 Final Year Project. Contributions are not accepted during evaluation period.

After grading, the project may be opened for community contributions.

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

**Note**: This is an educational prototype for defensive cybersecurity training. Use responsibly.

---

## 👤 Author

**Kalyan Gopinath**
- Student Number: 230656208
- Institution: University of London
- Programme: BSc Computer Science
- Module: CM3070 Final Year Project
- Submission: August 2026

---

## 🙏 Acknowledgments

- **MITRE ATT&CK Framework**: Threat behavior taxonomy
- **NIST SP 800-92**: Log management guidance
- **Streamlit Community**: Dashboard framework
- **Scikit-learn Team**: Machine learning library
- **University of London**: Academic supervision

---

## 📧 Contact

For academic inquiries: [Your university email]

**Project Repository**: https://github.com/yourusername/cybertriage

---

## 📊 Project Statistics

- **Lines of Code**: 2,500+
- **Test Coverage**: 63 tests, 100% pass
- **Documentation**: 10,000+ words
- **Visualizations**: 11 interactive charts
- **Evaluation Scenarios**: 80 labeled cases
- **Development Time**: 6 months
- **Version**: 2.0.0

---

## 🎥 Video Demonstration

[Link to 3-5 minute demonstration video]

Demonstrates:
- Core features and workflow
- AI model orchestration
- Evidence validation
- Advanced analytics
- Professional reporting

---

## 📖 Citation

If you use this work in academic research, please cite:

```bibtex
@misc{gopinath2026cybertriage,
  author = {Gopinath, Kalyan},
  title = {CyberTriage: AI-Assisted Cybersecurity Log Triage and Incident Explanation System},
  year = {2026},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://github.com/yourusername/cybertriage}}
}
```

---

## ⭐ Star History

If you find this project useful, please consider giving it a star! ⭐

---

**Built with ❤️ for defensive cybersecurity education**

🛡️ **CyberTriage** - Empowering analysts through transparent AI
