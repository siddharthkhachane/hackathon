# Screen Privacy Agent MVP

Fully local on-device demo for Google DeepMind x InstaLILY On-Device Hackathon.

Pipeline:
vision (screen or webcam) -> OCR -> Gemma reasoning (local Ollama) -> agent actions

No cloud calls are used.

## Files

- `shield_demo.py` main app
- `demo_leak.txt` fake leak content for demo
- `README.md` setup and demo guide

## Step 1: Environment setup

### 1) Files to create or modify

- Create `shield_demo.py`
- Create `demo_leak.txt`
- Update `README.md`

### 2) Exact commands to run

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install mss opencv-python pytesseract requests numpy
```

Ubuntu tesseract install:

```bash
sudo apt update
sudo apt install -y tesseract-ocr
tesseract --version
```

macOS tesseract install:

```bash
brew install tesseract
tesseract --version
```

Dependency verify:

```powershell
python -c "import cv2,mss,pytesseract,requests,numpy;print('deps_ok')"
```

### 3) Expected output

- `tesseract --version` prints version info
- verify command prints `deps_ok`

### 4) Common errors and fixes

- `ModuleNotFoundError`: activate virtual env and re-run pip install
- `tesseract is not recognized`: install Tesseract and add to PATH, then restart terminal
- On Windows if PATH is missing, set in PowerShell:

```powershell
$env:TESSERACT_CMD = "C:\Program Files\Tesseract-OCR\tesseract.exe"
```

## Step 2: Verify Ollama and Gemma

### 1) Files to create or modify

- No file changes needed

### 2) Exact commands to run

Install Ollama:

- macOS or Linux:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

- Windows: install from https://ollama.com/download/windows

Start Ollama service if needed:

```powershell
ollama serve
```

Pull and test model (choose one):

```powershell
ollama pull gemma3n
ollama run gemma3n "Return only JSON: {\"ok\":true}"
```

Fallback:

```powershell
ollama pull gemma3
ollama run gemma3 "Return only JSON: {\"ok\":true}"
```

HTTP check:

```powershell
curl http://localhost:11434/api/tags
```

### 3) Expected output

- Model pull progress and success
- `ollama run` returns JSON-like output
- tags endpoint returns installed model list

### 4) Common errors and fixes

- `connection refused`: run `ollama serve`
- model not found: run `ollama pull gemma3n` or `ollama pull gemma3`
- high latency: use `gemma3n` and reduce OCR items sent to model

## Step 3: Demo leak text file

### 1) Files to create or modify

- Create `demo_leak.txt`

### 2) Exact commands to run

Open `demo_leak.txt` in any editor and keep it visible on your screen during the demo.

### 3) Expected output

- Visible fake secrets are picked up by OCR and masked by the app

### 4) Common errors and fixes

- OCR misses text: increase font size and contrast, zoom editor to 125%+

## Step 4 to Step 10: Run the full MVP app

This single app includes:

- screen capture via `mss` with webcam fallback
- OCR via `pytesseract.image_to_data`
- regex sure-shot masking
- Gemma JSON action planning via local Ollama API
- agent actions: `MASK`, `BLOCK_SEND`, `ALLOW_SEND`, `LOG_EVENT`, risk level
- OpenCV HUD and event log
- keys: `s` shield toggle, `a` send simulation, `q` quit

### 1) Files to create or modify

- `shield_demo.py`

### 2) Exact commands to run

Run with default model:

```powershell
python shield_demo.py
```

Run with explicit model:

```powershell
python shield_demo.py --model gemma3n
```

If Tesseract path is custom on Windows:

```powershell
python shield_demo.py --tesseract-cmd "C:\Program Files\Tesseract-OCR\tesseract.exe"
```

Use webcam fallback directly:

```powershell
python shield_demo.py --force-webcam
```

### 3) Expected output

- Window opens: `Screen Privacy Agent`
- HUD shows shield status, risk, masked count, source
- Sensitive text regions are black-box masked in preview
- Press `a`:
	- risky content -> big red `BLOCKED` overlay and event log update
	- safe content -> green `ALLOWED` and sanitized transcript preview
- Press `s` toggles shield
- Press `q` exits cleanly

### 4) Common errors and fixes

- `TesseractNotFoundError`: install Tesseract and pass `--tesseract-cmd` on Windows
- blank screen capture: run with `--force-webcam`
- OpenCV window not appearing over remote desktop: run local session or use webcam mode
- OCR slow: keep app region smaller and close busy windows
- Ollama timeout: ensure model is pulled and reduce load with `--llm-topk 25`

## Demo script (2 to 3 minutes)

1. Open `demo_leak.txt` and keep it visible.
2. Start app: `python shield_demo.py --model gemma3n`.
3. Point to fake keys and emails, show automatic masks.
4. Press `a`, show `BLOCKED`.
5. Hide leak text and show neutral text.
6. Press `a`, show `ALLOWED` with sanitized preview.
7. Turn shield off and on using `s`.
8. Call out offline local mode text in HUD.

## Notes

- No training or fine-tuning is used.
- All processing stays local: capture, OCR, LLM, and action logic.
- This is MVP quality for fast demo shipping.
