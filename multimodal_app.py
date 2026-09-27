"""Three-domain companion UI; app.py remains the quantitative baseline."""
import hashlib
import json
from pathlib import Path
import streamlit as st
from cybertriage import multimodal as mm

st.set_page_config(page_title="CyberTriage | Multimodal case review", layout="wide")
st.title("CyberTriage — multimodal case review")
st.caption("Pre-trained image OCR • speech transcription • local text generation")
st.info("Educational prototype. Extracted text requires review. Spoken handover notes are unverified and never determine incident severity.")

if st.button("Run synthetic OCR and speech demonstration"):
    try:
        fixture_root = Path(__file__).parent / "multimodal_fixtures"
        with st.spinner("Running both local extraction models on labelled synthetic fixtures…"):
            st.session_state.image_extraction = mm.extract_image((fixture_root / "05_high_threshold_10_failures_clean.png").read_bytes())
            st.session_state.audio_extraction = mm.extract_audio((fixture_root / "note_01.wav").read_bytes())
        st.session_state.reviewed_logs = st.session_state.image_extraction.text
        st.session_state.reviewed_note = st.session_state.audio_extraction.text
        st.session_state.pop("case_result", None)
    except Exception as exc:
        st.error(f"Demonstration failed: {exc}")
st.caption("The demonstration runs inference, not cached predictions. Its spoken note is synthetic test input, not a human recording.")

image_col, audio_col = st.columns(2)
with image_col:
    st.subheader("1. Log screenshot → OCR")
    image = st.file_uploader("PNG or JPEG log screenshot", type=["png", "jpg", "jpeg"])
    if image is not None:
        st.image(image, caption="Source evidence image")
        image_hash = hashlib.sha256(image.getvalue()).hexdigest()
        if st.session_state.get("image_upload_hash") != image_hash:
            st.session_state.image_upload_hash = image_hash
            st.session_state.pop("image_extraction", None)
            st.session_state.pop("case_result", None)
            st.session_state.reviewed_logs = ""
    if st.button("Extract screenshot", disabled=image is None):
        try:
            with st.spinner("Running local EasyOCR…"):
                extraction = mm.extract_image(image.getvalue())
            st.session_state.image_extraction = extraction
            st.session_state.reviewed_logs = extraction.text
            st.session_state.pop("case_result", None)
        except Exception as exc:
            st.error(f"OCR failed ({type(exc).__name__}): {exc}")
    logs = st.text_area("Review / correct extracted SSH lines, or paste text logs",
                        key="reviewed_logs", height=230)
with audio_col:
    st.subheader("2. Spoken handover → transcript")
    audio = st.file_uploader("Analyst note (at most 120 seconds)", type=["wav", "mp3", "m4a", "flac"])
    if audio is not None:
        st.audio(audio)
        audio_hash = hashlib.sha256(audio.getvalue()).hexdigest()
        if st.session_state.get("audio_upload_hash") != audio_hash:
            st.session_state.audio_upload_hash = audio_hash
            st.session_state.pop("audio_extraction", None)
            st.session_state.pop("case_result", None)
            st.session_state.reviewed_note = ""
    if st.button("Transcribe handover", disabled=audio is None):
        try:
            with st.spinner("Running local Whisper base.en…"):
                extraction = mm.extract_audio(audio.getvalue())
            st.session_state.audio_extraction = extraction
            st.session_state.reviewed_note = extraction.text
            st.session_state.pop("case_result", None)
        except Exception as exc:
            st.error(f"Transcription failed ({type(exc).__name__}): {exc}")
    note = st.text_area("Review transcript — unverified analyst context",
                        key="reviewed_note", height=230)

st.subheader("3. Reviewed evidence → local LLM explanation")
digest = hashlib.sha256((logs + "\0" + note).encode()).hexdigest()
confirmed = st.checkbox("I have reviewed the text and kept handover claims separate from log evidence.", key=f"review_{digest}")
if st.button("Build case and run Llama 3", type="primary", disabled=not confirmed):
    try:
        case = mm.build_case(logs, note, reviewed=confirmed)
        with st.spinner("Generating an evidence-only explanation locally…"):
            case["explanation"] = mm.explain_case(case)
        case["provenance"] = [
            mm.extraction_record(st.session_state[key], text)
            for key, text in [("image_extraction", logs), ("audio_extraction", note)]
            if key in st.session_state]
        st.session_state.case_result = (digest, case)
    except Exception as exc:
        st.error(str(exc))

stored = st.session_state.get("case_result")
if stored and stored[0] == digest:
    case = stored[1]
    a, b, c = st.columns(3)
    a.metric("Rule classification", case["report"]["incident_type"])
    b.metric("Rule severity", case["detection"]["overall_severity"])
    c.metric("LLM status", case["explanation"]["status"])
    st.write(case["explanation"]["text"])
    unknown = sum(row["event_type"] == "unknown" for row in case["parsed_records"])
    if unknown:
        st.warning(f"{unknown} line(s) could not be parsed. Missing evidence may change the conclusion; check the source image and original logs.")
    st.json(case["report"]["evidence"])
    st.subheader("Unverified handover note")
    st.write(case["analyst_note_unverified"] or "No handover note supplied.")
    st.dataframe(case["parsed_records"], use_container_width=True)
    with st.expander("Model provenance and human corrections"):
        st.json(case["provenance"])
    st.download_button("Download reviewed case JSON", json.dumps(case, indent=2, default=str),
                       "cybertriage_case.json", "application/json")
st.caption("The original dashboard and Isolation Forest comparison remain available via: streamlit run app.py")
