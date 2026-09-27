"""Explicit one-time download; application inference never auto-downloads weights."""
from cybertriage.multimodal import MODEL_ROOT

if __name__ == "__main__":
    import easyocr
    from huggingface_hub import snapshot_download
    MODEL_ROOT.mkdir(exist_ok=True)
    easyocr.Reader(["en"], gpu=False,
                   model_storage_directory=str(MODEL_ROOT / "easyocr"), verbose=False)
    snapshot_download("Systran/faster-whisper-base.en",
                      local_dir=str(MODEL_ROOT / "whisper-base-en"))
    print("OCR and speech weights ready. LLM uses existing local llama3:latest.")
