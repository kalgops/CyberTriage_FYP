"""Record local model identities and dependency versions without redistributing weights."""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import urllib.request
from cybertriage.multimodal import MODEL_ROOT

root = Path(__file__).parent
record = {"packages": {name: importlib.metadata.version(name) for name in
                       ["easyocr", "faster-whisper", "torch", "torchvision", "ctranslate2"]},
          "weights": []}
for path in sorted(MODEL_ROOT.rglob("*")):
    if path.suffix in [".pth", ".bin"] and path.is_file():
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024*1024), b""):
                digest.update(chunk)
        record["weights"].append({"path": str(path.relative_to(MODEL_ROOT)),
                                  "sha256": digest.hexdigest()})
with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5) as response:
    record["ollama"] = [m for m in json.load(response)["models"] if m["name"] == "llama3:latest"]
(root / "evaluation_results/multimodal/environment.json").write_text(json.dumps(record,indent=2), encoding="utf-8")
print(json.dumps(record,indent=2))
