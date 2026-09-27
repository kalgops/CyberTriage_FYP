# Curated SSH validation logs

These 15 synthetic fixtures are readable contract examples, separate from the
80-scenario experiment and its 24/56 training/test split. They are not independent
security benchmarks and do not change the historical 83-test result.
All addresses use documentation ranges. No real accounts or traffic are included.

See manifest.json for each file's exact expected classifier label, detector
severity and purpose. The detector's benign severity is the string None, not
Normal. Three single-user failures produce Suspicious Login Pattern at Low;
multiple usernames escalate that case to Possible SSH Brute Force Attempt at Medium.

Run from the repository root:

```bash
python validate_test_logs.py
```

The checker asserts the independently specified rule outcomes. It does not assert
Isolation Forest predictions or reinterpret model anomalies as malicious intent.
Slow attempts and success after failures show limits of the count-based detector:
the former are aggregated across the entire input, and the latter are not a
sequence-aware compromise finding. Automation is labelled benign by construction.
The existing three UI samples and original evaluation dataset remain unchanged.
