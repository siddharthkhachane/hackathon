import argparse
import ctypes
import json
import re
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import cv2
import mss
import numpy as np
import pytesseract
import requests


@dataclass
class OCRItem:
    id: int
    text: str
    bbox: Tuple[int, int, int, int]
    conf: float
    sensitive: bool = False
    label: str = ""
    severity: str = "LOW"
    reason: str = ""
    line_key: Tuple[int, int, int] = (0, 0, 0)


SURE_SHOT_PATTERNS = [
    ("AWS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("PRIVATE_KEY", re.compile(r"BEGIN\s+PRIVATE\s+KEY", re.IGNORECASE)),
    ("PASSWORD", re.compile(r"password\s*[=:]\s*\S+", re.IGNORECASE)),
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
]


def safe_json_extract(raw: str) -> Optional[Dict]:
    try:
        return json.loads(raw)
    except Exception:
        pass
    first = raw.find("{")
    last = raw.rfind("}")
    if first == -1 or last == -1 or last <= first:
        return None
    chunk = raw[first : last + 1]
    try:
        return json.loads(chunk)
    except Exception:
        return None


def call_ollama_plan(
    model: str,
    ocr_items: List[OCRItem],
    timeout_s: float,
) -> Optional[Dict]:
    if not ocr_items:
        return {"risk_level": "LOW", "actions": []}

    payload_items = [
        {
            "id": item.id,
            "text": item.text,
            "conf": round(item.conf, 2),
            "bbox": list(item.bbox),
        }
        for item in ocr_items
    ]

    prompt = (
        "You are a local privacy policy agent.\n"
        "Given OCR items, decide sensitive items and output strict JSON only.\n"
        "Schema:\n"
        "{\n"
        '  "risk_level": "LOW|MEDIUM|HIGH",\n'
        '  "actions": [\n'
        "    {\n"
        '      "type": "MASK",\n'
        '      "id": <int>,\n'
        '      "label": "SHORT_LABEL",\n'
        '      "severity": "LOW|MEDIUM|HIGH",\n'
        '      "reason": "short reason"\n'
        "    }\n"
        "  ]\n"
        "}\n"
        "Only include MASK actions for items that should be hidden.\n"
        "No markdown. No explanation. JSON only.\n"
        f"OCR_ITEMS={json.dumps(payload_items, ensure_ascii=False)}"
    )

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
            timeout=timeout_s,
        )
        response.raise_for_status()
        data = response.json()
        text = data.get("response", "")
        parsed = safe_json_extract(text)
        return parsed
    except Exception:
        return None


def extract_ocr_items(frame_bgr: np.ndarray, min_conf: float = 35.0) -> List[OCRItem]:
    gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
    data = pytesseract.image_to_data(
        gray,
        output_type=pytesseract.Output.DICT,
        config="--oem 3 --psm 6",
    )
    items: List[OCRItem] = []
    raw_count = len(data.get("text", []))
    running_id = 1
    for idx in range(raw_count):
        text = (data["text"][idx] or "").strip()
        conf_text = str(data["conf"][idx]).strip()
        if not text:
            continue
        try:
            conf = float(conf_text)
        except Exception:
            conf = -1.0
        if conf < min_conf:
            continue
        x = int(data["left"][idx])
        y = int(data["top"][idx])
        w = int(data["width"][idx])
        h = int(data["height"][idx])
        if w <= 0 or h <= 0:
            continue
        line_key = (
            int(data.get("block_num", [0] * raw_count)[idx]),
            int(data.get("par_num", [0] * raw_count)[idx]),
            int(data.get("line_num", [0] * raw_count)[idx]),
        )
        items.append(OCRItem(id=running_id, text=text, bbox=(x, y, w, h), conf=conf, line_key=line_key))
        running_id += 1
    return items


def apply_regex_baseline(items: List[OCRItem]) -> List[int]:
    masked_ids = []

    line_groups: Dict[Tuple[int, int, int], List[OCRItem]] = {}
    for item in items:
        line_groups.setdefault(item.line_key, []).append(item)

    for line_items in line_groups.values():
        line_text = " ".join(i.text for i in line_items)
        for label, pattern in SURE_SHOT_PATTERNS:
            if pattern.search(line_text):
                for line_item in line_items:
                    line_item.sensitive = True
                    line_item.label = label
                    line_item.severity = "HIGH" if label in {"AWS_KEY", "JWT", "PRIVATE_KEY", "PASSWORD"} else "MEDIUM"
                    line_item.reason = "Regex baseline"
                    masked_ids.append(line_item.id)
                break

    for item in items:
        if item.sensitive:
            continue
        for label, pattern in SURE_SHOT_PATTERNS:
            if pattern.search(item.text):
                item.sensitive = True
                item.label = label
                item.severity = "HIGH" if label in {"AWS_KEY", "JWT", "PRIVATE_KEY", "PASSWORD"} else "MEDIUM"
                item.reason = "Regex baseline"
                masked_ids.append(item.id)
                break
    return masked_ids


def get_window_rect_windows(title: str) -> Optional[Tuple[int, int, int, int]]:
    try:
        user32 = ctypes.windll.user32
        hwnd = user32.FindWindowW(None, title)
        if not hwnd:
            return None

        class RECT(ctypes.Structure):
            _fields_ = [
                ("left", ctypes.c_long),
                ("top", ctypes.c_long),
                ("right", ctypes.c_long),
                ("bottom", ctypes.c_long),
            ]

        rect = RECT()
        ok = user32.GetWindowRect(hwnd, ctypes.byref(rect))
        if not ok:
            return None
        return rect.left, rect.top, rect.right, rect.bottom
    except Exception:
        return None


def hide_own_preview_in_capture(frame: np.ndarray, monitor: Dict, window_rect: Optional[Tuple[int, int, int, int]]):
    if not window_rect:
        return
    wx1, wy1, wx2, wy2 = window_rect
    mx1 = int(monitor.get("left", 0))
    my1 = int(monitor.get("top", 0))
    mx2 = mx1 + int(monitor.get("width", frame.shape[1]))
    my2 = my1 + int(monitor.get("height", frame.shape[0]))

    ix1 = max(wx1, mx1)
    iy1 = max(wy1, my1)
    ix2 = min(wx2, mx2)
    iy2 = min(wy2, my2)
    if ix2 <= ix1 or iy2 <= iy1:
        return

    rx1 = ix1 - mx1
    ry1 = iy1 - my1
    rx2 = ix2 - mx1
    ry2 = iy2 - my1
    cv2.rectangle(frame, (rx1, ry1), (rx2, ry2), (30, 30, 30), -1)


def apply_model_actions(items: List[OCRItem], plan: Optional[Dict]) -> Tuple[str, List[int], bool]:
    risk_level = "LOW"
    parse_ok = True
    if not plan:
        return risk_level, [], False

    risk_level = str(plan.get("risk_level", "LOW")).upper()
    if risk_level not in {"LOW", "MEDIUM", "HIGH"}:
        risk_level = "LOW"

    by_id = {item.id: item for item in items}
    masked = []
    actions = plan.get("actions", [])
    if not isinstance(actions, list):
        return risk_level, masked, False

    for action in actions:
        if not isinstance(action, dict):
            parse_ok = False
            continue
        if str(action.get("type", "")).upper() != "MASK":
            continue
        action_id = action.get("id")
        if not isinstance(action_id, int):
            parse_ok = False
            continue
        item = by_id.get(action_id)
        if not item:
            continue
        item.sensitive = True
        item.label = str(action.get("label", "MODEL_MASK"))[:32]
        sev = str(action.get("severity", "MEDIUM")).upper()
        if sev not in {"LOW", "MEDIUM", "HIGH"}:
            sev = "MEDIUM"
        item.severity = sev
        item.reason = str(action.get("reason", "Model policy"))[:120]
        masked.append(item.id)
    return risk_level, masked, parse_ok


def sanitize_transcript(items: List[OCRItem], sensitive_ids: set) -> str:
    chunks = []
    for item in items:
        if item.id in sensitive_ids:
            chunks.append("████")
        else:
            chunks.append(item.text)
    return " ".join(chunks)


def draw_text_block(frame: np.ndarray, lines: List[str], origin: Tuple[int, int], color=(255, 255, 255), bg=(20, 20, 20)):
    x, y = origin
    font = cv2.FONT_HERSHEY_SIMPLEX
    scale = 0.5
    thickness = 1
    line_h = 18
    width = 0
    for line in lines:
        tw, _ = cv2.getTextSize(line, font, scale, thickness)[0]
        width = max(width, tw)
    cv2.rectangle(frame, (x - 6, y - 16), (x + width + 8, y + line_h * len(lines)), bg, -1)
    for i, line in enumerate(lines):
        cv2.putText(frame, line, (x, y + i * line_h), font, scale, color, thickness, cv2.LINE_AA)


def open_capture(force_webcam: bool = False, allow_webcam_fallback: bool = False):
    if force_webcam:
        cap = cv2.VideoCapture(0)
        if cap.isOpened():
            return "webcam", cap
        return None, None

    try:
        sct = mss.mss()
        return "screen", sct
    except Exception:
        if not allow_webcam_fallback:
            return None, None
        cap = cv2.VideoCapture(0)
        if cap.isOpened():
            return "webcam", cap
        return None, None


def get_frame(source_kind: str, source_obj):
    if source_kind == "screen":
        monitor = source_obj.monitors[1]
        raw = source_obj.grab(monitor)
        frame = np.array(raw)
        frame_bgr = cv2.cvtColor(frame, cv2.COLOR_BGRA2BGR)
        window_rect = get_window_rect_windows("Screen Privacy Agent")
        hide_own_preview_in_capture(frame_bgr, monitor, window_rect)
        return frame_bgr
    ret, frame = source_obj.read()
    if not ret:
        return None
    return frame


def main():
    parser = argparse.ArgumentParser(description="Local Screen Privacy Agent MVP")
    parser.add_argument("--model", default="gemma3n", help="Ollama model name: gemma3n or gemma3")
    parser.add_argument("--ocr-interval", type=float, default=0.7, help="OCR interval seconds")
    parser.add_argument("--min-conf", type=float, default=20.0, help="OCR confidence threshold")
    parser.add_argument("--llm-topk", type=int, default=35, help="Max OCR items sent to LLM")
    parser.add_argument("--ollama-timeout", type=float, default=4.5, help="Timeout in seconds for Ollama call")
    parser.add_argument("--force-webcam", action="store_true", help="Use webcam instead of screen capture")
    parser.add_argument(
        "--allow-webcam-fallback",
        action="store_true",
        help="Allow webcam only if screen capture fails",
    )
    parser.add_argument("--tesseract-cmd", default="", help="Optional explicit tesseract executable path")
    args = parser.parse_args()

    if args.tesseract_cmd.strip():
        pytesseract.pytesseract.tesseract_cmd = args.tesseract_cmd.strip()

    source_kind, source_obj = open_capture(
        force_webcam=args.force_webcam,
        allow_webcam_fallback=args.allow_webcam_fallback,
    )
    if not source_obj:
        print("Failed to open screen capture")
        print("Run with --allow-webcam-fallback or --force-webcam if you want webcam mode")
        return

    shield_on = True
    risk_level = "LOW"
    overlay_message = ""
    overlay_until = 0.0
    events = deque(maxlen=5)

    last_ocr_ts = 0.0
    latest_items: List[OCRItem] = []
    latest_sensitive_ids: set = set()
    latest_parse_ok = True

    cv2.namedWindow("Screen Privacy Agent", cv2.WINDOW_NORMAL)

    while True:
        frame = get_frame(source_kind, source_obj)
        if frame is None:
            break

        now = time.time()
        if now - last_ocr_ts >= args.ocr_interval:
            last_ocr_ts = now
            try:
                items = extract_ocr_items(frame, min_conf=args.min_conf)
            except Exception as exc:
                events.appendleft(f"OCR error: {str(exc)[:60]}")
                items = []

            baseline_ids = set(apply_regex_baseline(items))

            sorted_for_model = sorted(items, key=lambda it: it.conf, reverse=True)
            model_candidates = sorted_for_model[: max(1, args.llm_topk)]
            plan = call_ollama_plan(args.model, model_candidates, timeout_s=args.ollama_timeout)
            model_risk, model_ids, parse_ok = apply_model_actions(items, plan)
            latest_parse_ok = parse_ok

            merged_sensitive = baseline_ids.union(set(model_ids))

            if any(it.id in merged_sensitive and it.severity == "HIGH" for it in items):
                risk_level = "HIGH"
            elif model_risk in {"MEDIUM", "HIGH"}:
                risk_level = model_risk
            elif merged_sensitive:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            latest_items = items
            latest_sensitive_ids = merged_sensitive

            if not parse_ok:
                events.appendleft("Model parse fallback active")

        display = frame.copy()
        masked_count = 0
        if shield_on:
            for item in latest_items:
                if item.id in latest_sensitive_ids:
                    x, y, w, h = item.bbox
                    cv2.rectangle(display, (x, y), (x + w, y + h), (0, 0, 0), -1)
                    masked_count += 1

        hud_color = (0, 255, 0) if shield_on else (0, 165, 255)
        risk_color = (0, 220, 0) if risk_level == "LOW" else ((0, 180, 255) if risk_level == "MEDIUM" else (0, 0, 255))

        hud_lines = [
            f"Shield: {'ON' if shield_on else 'OFF'}",
            f"Risk: {risk_level}",
            f"Masked: {masked_count}",
            f"Source: {source_kind}",
            f"Local mode: internet not required",
        ]
        draw_text_block(display, hud_lines, (12, 26), color=(255, 255, 255), bg=(30, 30, 30))
        cv2.putText(display, f"Shield {'ON' if shield_on else 'OFF'}", (14, 20), cv2.FONT_HERSHEY_SIMPLEX, 0.55, hud_color, 2, cv2.LINE_AA)
        cv2.putText(display, f"Risk {risk_level}", (160, 20), cv2.FONT_HERSHEY_SIMPLEX, 0.55, risk_color, 2, cv2.LINE_AA)

        log_lines = ["Events:"] + list(events)[:5]
        draw_text_block(display, log_lines, (12, max(110, display.shape[0] - 120)), color=(220, 220, 220), bg=(22, 22, 22))

        if time.time() < overlay_until and overlay_message:
            overlay_color = (0, 0, 255) if overlay_message.startswith("BLOCKED") else (0, 255, 0)
            cv2.putText(
                display,
                overlay_message,
                (max(20, display.shape[1] // 4), display.shape[0] // 2),
                cv2.FONT_HERSHEY_SIMPLEX,
                1.3,
                overlay_color,
                3,
                cv2.LINE_AA,
            )

        cv2.imshow("Screen Privacy Agent", display)
        if cv2.getWindowProperty("Screen Privacy Agent", cv2.WND_PROP_VISIBLE) < 1:
            break
        key = cv2.waitKey(1) & 0xFF

        if key == ord("q"):
            break
        if key == 27:
            break
        if key == ord("x"):
            break
        if key == ord("s"):
            shield_on = not shield_on
            events.appendleft(f"Shield {'ON' if shield_on else 'OFF'}")
        if key == ord("a"):
            transcript = " ".join(item.text for item in latest_items)
            sanitized = sanitize_transcript(latest_items, latest_sensitive_ids)
            has_high = any(item.id in latest_sensitive_ids and item.severity == "HIGH" for item in latest_items)
            if has_high or len(latest_sensitive_ids) > 0:
                overlay_message = f"BLOCKED ({risk_level})"
                events.appendleft("BLOCK_SEND: sensitive content detected")
                events.appendleft("LOG_EVENT: send blocked")
            else:
                overlay_message = "ALLOWED"
                preview = sanitized[:100].replace("\n", " ")
                events.appendleft(f"ALLOW_SEND: {preview}")
                events.appendleft("LOG_EVENT: send allowed")
            overlay_until = time.time() + 1.8

            if transcript.strip() and sanitized.strip() and transcript != sanitized:
                events.appendleft("Sanitized transcript applied")

    if source_kind == "webcam" and source_obj:
        source_obj.release()
    if source_kind == "screen" and source_obj:
        source_obj.close()
    cv2.destroyAllWindows()


if __name__ == "__main__":
    main()