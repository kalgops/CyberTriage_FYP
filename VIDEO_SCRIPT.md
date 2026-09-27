# CyberTriage - Video Demonstration Script
## Duration: 3-5 minutes

---

## **SCENE 1: Introduction (30 seconds)**

### Visual: Title screen with CyberTriage logo and gradient background

**Narration:**
"Hello, I'm presenting CyberTriage - an AI-assisted cybersecurity log triage and incident explanation system. This project demonstrates how multiple AI models can be orchestrated to transform raw security logs into actionable intelligence while maintaining complete transparency and evidence provenance.

CyberTriage addresses a critical gap in security operations: helping junior analysts quickly understand and respond to authentication threats without requiring years of experience."

### Visual: Transition to dashboard homepage

---

## **SCENE 2: Problem Demonstration (30 seconds)**

### Visual: Show raw SSH log text in notepad

**Narration:**
"Security teams face a challenge: authentication logs like these contain valuable threat intelligence, but they're difficult to interpret. Is this normal activity or a brute-force attack? How severe is the threat? What should an analyst do next?

Traditional tools either provide raw data without explanation, or use black-box AI that can't justify its decisions. CyberTriage solves this by combining transparent rule-based detection with machine learning, while preserving complete evidence traceability."

### Visual: Highlight confusing aspects of raw logs

---

## **SCENE 3: Core Features Demo (90 seconds)**

### Visual: Load "Brute Force Attack" sample

**Narration:**
"Let me demonstrate the system's capabilities. I'll load a sample containing a brute-force attack pattern."

### Visual: Click "Brute Force Attack" button

**Narration:**
"The system immediately parses the logs, extracting timestamps, usernames, source IPs, and event types. Notice how it supports both IPv4 and IPv6 addresses, as well as password and public-key authentication."

### Visual: Click "Analyze" button, show loading animation

**Narration:**
"During analysis, CyberTriage applies deterministic threshold rules: 3-4 failures trigger low severity, 5-9 trigger medium, and 10 or more trigger high severity. The system also escalates severity when multiple usernames are targeted, indicating password spraying behavior."

### Visual: Show results - alert banner

**Narration:**
"The results clearly identify this as a 'Possible SSH Brute Force Attempt' with high severity. The system detected 18 failed login attempts from IP address 192.168.1.45, targeting 8 different usernames over a 2-minute window."

### Visual: Scroll to metric cards

**Narration:**
"These gradient metric cards provide at-a-glance threat assessment. Notice the color-coding: red for high severity, making the threat level immediately obvious."

---

## **SCENE 4: AI Model Orchestration (60 seconds)**

### Visual: Scroll to "AI Model Comparison" section

**Narration:**
"Here's where the AI orchestration becomes evident. CyberTriage doesn't rely on a single approach - it compares rule-based detection with an Isolation Forest machine learning model trained on 24 normal behavior patterns."

### Visual: Show comparison table

**Narration:**
"The rule-based detector flagged this IP as suspicious based on the threshold violation. The Isolation Forest also detected it as an anomaly, with a high anomaly score. This agreement increases confidence in the assessment.

Importantly, when models disagree, that disagreement is preserved and displayed - it's valuable information that prompts analyst review rather than being hidden by averaging."

### Visual: Show threat gauge and timeline chart

**Narration:**
"The threat assessment gauge visualizes the severity on a 0-100 scale, while the timeline chart shows the rapid succession of failed attempts - a clear indicator of automated attack behavior."

---

## **SCENE 5: Advanced Analytics (45 seconds)**

### Visual: Click through analytics tabs

**Narration:**
"The Advanced Analytics section provides deeper insights. The attack pattern radar chart shows five dimensions of threat characteristics: failed attempts, username diversity, persistence, velocity, and severity score.

The threat heatmap reveals activity patterns by time and source IP, helping identify when attacks occur. The statistics tab provides comprehensive metrics: 18 total events, 1 unique IP, 8 targeted users, and a 0% success rate - all indicators of a failed brute-force attempt."

### Visual: Show feature importance chart

**Narration:**
"The feature importance chart demonstrates which behavioral features the machine learning model considers most significant. This transparency is crucial - analysts can understand *why* the model flagged something as suspicious."

---

## **SCENE 6: Evidence and Explainability (30 seconds)**

### Visual: Scroll to incident explanation

**Narration:**
"CyberTriage prioritizes explainability. The incident explanation is grounded strictly in parsed evidence - no invented facts. The system can optionally use a local Ollama language model to rephrase the explanation in natural language, but crucially, the LLM output is validated against the evidence.

If the LLM tries to invent IP addresses, counts, or unsupported claims like 'system compromised,' the output is rejected and the system falls back to a deterministic template. This validation framework is a novel contribution of this project."

### Visual: Show evidence summary section

---

## **SCENE 7: Professional Reporting (30 seconds)**

### Visual: Scroll to recommended actions

**Narration:**
"The system provides actionable recommendations: check if any attempts succeeded, review logs for similar activity, consider blocking the source IP, and review SSH hardening controls. These aren't vague suggestions - they're specific investigative steps."

### Visual: Show export section

**Narration:**
"Analysts can export findings in three formats: plain text for quick sharing, CSV for further analysis, and professional PDF reports for documentation. The PDF includes all analysis, visualizations, evidence tables, and technical details."

### Visual: Click "Download PDF Report" button

---

## **SCENE 8: Technical Excellence (30 seconds)**

### Visual: Show code editor with test files

**Narration:**
"The system is backed by rigorous engineering: 63 automated tests covering parsing, detection, classification, and validation. All tests pass, ensuring reliability.

The evaluation on 80 synthetic scenarios shows the rule-based detector achieves perfect precision and recall, while the Isolation Forest provides complementary anomaly detection with high precision but conservative recall - exactly what we want for a supplementary model."

### Visual: Show evaluation results CSV

---

## **SCENE 9: Conclusion (30 seconds)**

### Visual: Return to dashboard, show different sample

**Narration:**
"Let me quickly demonstrate with a normal activity sample."

### Visual: Load "Normal Activity" sample, analyze

**Narration:**
"Notice how the system correctly identifies this as 'Normal Activity' with low risk. The visualizations show successful logins with minimal failures - exactly what we expect from legitimate use.

CyberTriage demonstrates that AI-assisted security tools can be powerful, transparent, and safe. By orchestrating multiple analytical approaches while preserving evidence provenance, the system empowers analysts rather than replacing them."

### Visual: Final title screen with key achievements

**Narration:**
"Key achievements: robust multi-format log parsing, deterministic detection with ML comparison, LLM validation framework, 11 interactive visualizations, professional PDF reports, and comprehensive testing. Thank you for watching."

---

## **Recording Tips**

### **Visual Requirements:**
1. **Screen recording**: 1920x1080 minimum resolution
2. **Cursor highlighting**: Enable for clarity
3. **Smooth transitions**: No jarring cuts
4. **Clear text**: Zoom in on important details
5. **Professional appearance**: Clean desktop, no distractions

### **Audio Requirements:**
1. **Clear voice**: Use good microphone
2. **Steady pace**: Not too fast, not too slow
3. **Enthusiasm**: Show passion for the project
4. **No AI voices**: Must be your own voice
5. **No speed-up**: Natural speaking pace

### **Content Checklist:**
- ✅ Show problem/motivation
- ✅ Demonstrate core features
- ✅ Explain AI orchestration
- ✅ Show advanced analytics
- ✅ Demonstrate evidence validation
- ✅ Show professional reporting
- ✅ Highlight technical excellence
- ✅ Compare normal vs. attack scenarios
- ✅ Mention key achievements
- ✅ Stay within 3-5 minutes

### **Suggested Recording Software:**
- **OBS Studio** (free, professional)
- **Camtasia** (paid, easy editing)
- **Loom** (free, simple)
- **Windows Game Bar** (built-in)

### **Editing Tips:**
1. Add title cards for each section
2. Highlight important UI elements with circles/arrows
3. Add subtle background music (low volume)
4. Include captions/subtitles for accessibility
5. Export as MP4 (H.264 codec)

---

## **Timing Breakdown**

| Section | Duration | Cumulative |
|---------|----------|------------|
| Introduction | 30s | 0:30 |
| Problem Demo | 30s | 1:00 |
| Core Features | 90s | 2:30 |
| AI Orchestration | 60s | 3:30 |
| Advanced Analytics | 45s | 4:15 |
| Evidence/Explainability | 30s | 4:45 |
| Professional Reporting | 30s | 5:15 |
| Technical Excellence | 30s | 5:45 |
| Conclusion | 30s | 6:15 |

**Target**: Aim for 4:30-5:00 by adjusting pace

---

## **Key Messages to Emphasize**

1. **AI Orchestration**: Multiple models working together
2. **Transparency**: Complete evidence provenance
3. **Safety**: LLM validation framework
4. **Usability**: Professional visualizations and reports
5. **Rigor**: Comprehensive testing and evaluation
6. **Originality**: Novel validation approach
7. **Impact**: Empowers junior analysts

---

## **Common Mistakes to Avoid**

❌ Speaking too fast (rushing through features)
❌ Not explaining *why* features matter
❌ Showing only one scenario type
❌ Forgetting to mention AI orchestration
❌ Not highlighting novel contributions
❌ Exceeding 5-minute limit
❌ Poor audio quality
❌ Cluttered screen/distractions
❌ No clear narrative structure
❌ Forgetting to show working features

✅ **Do**: Tell a story, show impact, explain decisions, demonstrate thoroughly

---

## **Post-Recording Checklist**

- [ ] Video is 3-5 minutes long
- [ ] Audio is clear and at good volume
- [ ] All key features demonstrated
- [ ] AI orchestration explained
- [ ] Novel contributions highlighted
- [ ] Both attack and normal scenarios shown
- [ ] Exported as MP4 format
- [ ] File size reasonable (<500MB)
- [ ] Tested playback on different devices
- [ ] Ready for submission

---

**Good luck with your recording!** 🎥
