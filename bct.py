import sys
import re
import copy
import json
import base64
from urllib.parse import urlparse, urlunparse
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLabel, QLineEdit, QFrame,
    QSizePolicy, QCheckBox
)
from PyQt5.QtCore import Qt, QTimer, QRect, QThread, pyqtSignal
from PyQt5.QtGui import (
    QColor, QPainter, QLinearGradient, QFont,
    QPalette, QCursor
)

DARK_BG    = "#0d0d12"
PANEL_BG   = "#13131c"
CARD_BG    = "#1a1a27"
BORDER     = "#2a2a3d"
ACCENT     = "#6c63ff"
ACCENT2    = "#a78bfa"
SUCCESS    = "#22d3a5"
WARNING    = "#f59e0b"
DANGER     = "#f87171"
TEXT_PRI   = "#e8e6f0"
TEXT_SEC   = "#8b8aad"
TEXT_MUTED = "#4a4a6a"

HTTP_PORTS = {"80", "8080", "8880", "2052", "2082", "2086", "2095"}
PROXY_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}

STYLESHEET = f"""
QMainWindow, QWidget#root {{
    background-color: {DARK_BG};
}}
QWidget {{
    font-family: 'JetBrains Mono', 'Consolas', 'Courier New', monospace;
    color: {TEXT_PRI};
}}
QTextEdit {{
    background-color: {CARD_BG};
    border: 1.5px solid {BORDER};
    border-radius: 12px;
    padding: 16px;
    font-size: 12px;
    color: {TEXT_PRI};
    selection-background-color: {ACCENT};
}}
QTextEdit:focus {{
    border: 1.5px solid {ACCENT};
}}
QLineEdit {{
    background-color: {CARD_BG};
    border: 1.5px solid {BORDER};
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 13px;
    color: {TEXT_PRI};
}}
QLineEdit:focus {{
    border: 1.5px solid {ACCENT};
    background-color: #1e1e2e;
}}
QCheckBox {{
    spacing: 8px;
    font-size: 11px;
    color: {TEXT_SEC};
    padding: 4px 0;
}}
QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border-radius: 4px;
    border: 1.5px solid {BORDER};
    background: {CARD_BG};
}}
QCheckBox::indicator:checked {{
    background: {ACCENT};
    border: 1.5px solid {ACCENT};
}}
QScrollBar:vertical {{
    background: {PANEL_BG};
    width: 6px;
    border-radius: 3px;
}}
QScrollBar::handle:vertical {{
    background: {BORDER};
    border-radius: 3px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {ACCENT};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    height: 0;
}}
"""


# ---------------------------------------------------------------------------
# URL-based config helpers
# ---------------------------------------------------------------------------

def is_v2ray_config(text):
    protocols = [
        "vless://", "vmess://", "trojan://", "ss://", "ssr://",
        "tuic://", "hysteria://", "hysteria2://", "hy2://"
    ]
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]
    return bool(lines) and any(
        any(l.startswith(p) for p in protocols) for l in lines
    )


def try_decode_base64(text):
    try:
        clean = re.sub(r"\s+", "", text.strip())
        if not clean:
            return None
        pad = len(clean) % 4
        if pad:
            clean += "=" * (4 - pad)
        decoded = base64.b64decode(clean).decode("utf-8", errors="ignore")
        return decoded if is_v2ray_config(decoded) else None
    except Exception:
        return None


def export_base64(text):
    return base64.b64encode(text.encode()).decode()


def extract_url_configs(text):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    result = []
    for line in lines:
        if is_v2ray_config(line):
            result.append(line)
        else:
            decoded = try_decode_base64(line)
            if decoded:
                result.extend(
                    l.strip()
                    for l in decoded.splitlines()
                    if l.strip()
                )
    return "\n".join(result)


# ---------------------------------------------------------------------------
# JSON config helpers
# ---------------------------------------------------------------------------

def _has_proxy_outbound(config):
    if not isinstance(config, dict):
        return False
    for ob in config.get("outbounds", []):
        if ob.get("protocol") in PROXY_PROTOCOLS:
            return True
    return False


def is_json_config(text):
    stripped = text.strip()
    if not (stripped.startswith("[") or stripped.startswith("{")):
        return False
    try:
        data = json.loads(stripped)
        if isinstance(data, list):
            return any(_has_proxy_outbound(i) for i in data if isinstance(i, dict))
        return _has_proxy_outbound(data)
    except Exception:
        return False


def _transform_json_single(config, minimal_mode=False, insecure_mode=False):
    config = copy.deepcopy(config)
    for outbound in config.get("outbounds", []):
        proto = outbound.get("protocol", "")
        if proto not in PROXY_PROTOCOLS:
            continue
        settings  = outbound.get("settings", {})
        stream    = outbound.get("streamSettings", {})
        ws        = stream.get("wsSettings", {})
        host_hdr  = ws.get("host", "")
        orig_addr = ""

        for key in ("vnext", "servers"):
            for entry in settings.get(key, []):
                if not orig_addr:
                    orig_addr = entry.get("address", "")
                entry["address"] = "127.0.0.1"
                entry["port"]    = 40443

        sni_src = host_hdr or orig_addr

        if stream.get("security", "none").lower() in ("none", ""):
            stream["security"] = "tls"

        tls = stream.get("tlsSettings", {})
        if not tls.get("serverName") and sni_src:
            tls["serverName"]   = sni_src
        tls.setdefault("fingerprint", "random")
        tls.pop("ech",         None)
        tls.pop("echSettings", None)
        tls["allowInsecure"] = insecure_mode
        stream["tlsSettings"] = tls

        if minimal_mode and "wsSettings" in stream:
            stream["wsSettings"]["path"] = "/"

        outbound["streamSettings"] = stream
        outbound["settings"]       = settings
    return config


def transform_json_configs(text, minimal_mode=False, insecure_mode=False):
    data = json.loads(text.strip())
    if isinstance(data, list):
        out = [
            _transform_json_single(i, minimal_mode, insecure_mode)
            if isinstance(i, dict) and _has_proxy_outbound(i) else i
            for i in data
        ]
    else:
        out = _transform_json_single(data, minimal_mode, insecure_mode)
    return json.dumps(out, indent=4, ensure_ascii=False)


def count_json_configs(text):
    try:
        data = json.loads(text.strip())
        if isinstance(data, list):
            return sum(1 for i in data if isinstance(i, dict) and _has_proxy_outbound(i))
        return 1 if _has_proxy_outbound(data) else 0
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Unified input detection
# ---------------------------------------------------------------------------

def detect_and_extract(raw):
    """
    Returns (mode, extracted_text, count)
    mode: 'json' | 'url' | 'b64' | 'unknown'
    """
    stripped = raw.strip()
    if not stripped:
        return ("unknown", "", 0)

    if is_json_config(stripped):
        n = count_json_configs(stripped)
        return ("json", stripped, n)

    extracted = extract_url_configs(stripped)
    if extracted.strip():
        lines = [l for l in extracted.splitlines() if l.strip()]
        raw_lines = [l for l in stripped.splitlines() if l.strip()]
        mode = "b64" if len(raw_lines) < len(lines) else "url"
        return (mode, extracted, len(lines))

    return ("unknown", stripped, 0)


# ---------------------------------------------------------------------------
# URL transform core
# ---------------------------------------------------------------------------

def _decode_vmess(line):
    b64 = line[len("vmess://"):]
    pad = 4 - len(b64) % 4
    if pad != 4:
        b64 += "=" * pad
    return json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))


def _encode_vmess(data):
    return "vmess://" + base64.b64encode(
        json.dumps(data, separators=(",", ":")).encode()
    ).decode()


def _parse_query_raw(qs):
    params = []
    if not qs:
        return params
    for part in qs.split("&"):
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            params.append([k, v])
        else:
            params.append([part, None])
    return params


def _build_query_raw(params):
    return "&".join(k if v is None else f"{k}={v}" for k, v in params)


def _index_map(params):
    return {k.lower(): i for i, (k, _) in enumerate(params)}


def _set_or_add(params, key, value):
    idx = _index_map(params)
    if key.lower() in idx:
        params[idx[key.lower()]][1] = value
    else:
        params.append([key, value])


def transform_sni_spoof(line, minimal_mode=False, insecure_mode=False):
    line = line.strip()
    if not line:
        return line
    frag = ""
    if "#" in line:
        i    = line.index("#")
        frag = line[i:]
        line = line[:i]

    if line.startswith("vmess://"):
        try:
            data = _decode_vmess(line)
            data["add"]  = "127.0.0.1"
            data["port"] = "40443"
            if str(data.get("tls", "")).lower() in ("", "none", "0", "false"):
                data["tls"] = "tls"
            if not data.get("sni"):
                data["sni"] = data.get("host") or ""
            data["fp"] = data.get("fp") or "random"
            data.pop("ech", None)
            if minimal_mode:
                data["path"] = "/"
            data["allowInsecure"] = 1 if insecure_mode else 0
            return _encode_vmess(data) + frag
        except Exception:
            return line + frag

    supported = ["vless://", "trojan://", "ss://"]
    if not any(line.startswith(p) for p in supported):
        return line + frag

    base_part, qs = line.split("?", 1) if "?" in line else (line, "")
    parsed  = urlparse(base_part)
    netloc  = parsed.netloc
    userinfo, hostpart = netloc.rsplit("@", 1) if "@" in netloc else (None, netloc)
    original_host = hostpart.rsplit(":", 1)[0] if ":" in hostpart else hostpart

    params          = _parse_query_raw(qs)
    host_param_val  = next((v for k, v in params if k.lower() == "host"), None)
    sni_source      = host_param_val if host_param_val else original_host

    params = [[k, v] for k, v in params if not k.lower().startswith("ech")]

    idx = _index_map(params)
    if "security" in idx:
        if params[idx["security"]][1].lower() in ("none", ""):
            params[idx["security"]][1] = "tls"
    else:
        _set_or_add(params, "security", "tls")

    if "sni" not in _index_map(params) and sni_source:
        params.append(["sni", sni_source])
    _set_or_add(params, "fp", params[_index_map(params)["fp"]][1]
                if "fp" in _index_map(params) else "random")

    iv = "1" if insecure_mode else "0"
    _set_or_add(params, "insecure",      iv)
    _set_or_add(params, "allowInsecure", iv)

    if minimal_mode:
        _set_or_add(params, "path", "%2F")

    new_netloc = f"{userinfo}@127.0.0.1:40443" if userinfo else "127.0.0.1:40443"
    new_parsed = parsed._replace(netloc=new_netloc, query=_build_query_raw(params))
    return urlunparse(new_parsed) + frag


def process_sni_spoof(text, minimal_mode=False, insecure_mode=False):
    return "\n".join(
        transform_sni_spoof(l, minimal_mode, insecure_mode)
        for l in text.splitlines() if l.strip()
    )


def simple_replace(line, new_host=None, new_port=None):
    line = line.strip()
    if not line:
        return line
    if line.startswith("vmess://"):
        try:
            data = _decode_vmess(line)
            if new_host:
                data["add"]  = new_host
            if new_port:
                data["port"] = new_port
            return _encode_vmess(data)
        except Exception:
            return line
    frag = ""
    if "#" in line:
        i    = line.index("#")
        frag = line[i:]
        line = line[:i]
    base_part, qs = line.split("?", 1) if "?" in line else (line, "")
    parsed  = urlparse(base_part)
    netloc  = parsed.netloc
    userinfo, hostpart = netloc.rsplit("@", 1) if "@" in netloc else (None, netloc)
    host = hostpart.rsplit(":", 1)[0] if ":" in hostpart else hostpart
    port = hostpart.rsplit(":", 1)[1] if ":" in hostpart else ""
    fh   = new_host if new_host else host
    fp   = new_port if new_port else port
    new_netloc = f"{userinfo}@{fh}:{fp}" if userinfo else f"{fh}:{fp}"
    new_parsed = parsed._replace(netloc=new_netloc, query=qs)
    return urlunparse(new_parsed) + frag


def process_simple(text, new_host=None, new_port=None):
    return "\n".join(
        simple_replace(l, new_host, new_port) if l.strip() else ""
        for l in text.splitlines()
    )


# ---------------------------------------------------------------------------
# Background workers (prevent UI freeze)
# ---------------------------------------------------------------------------

class ExtractWorker(QThread):
    finished = pyqtSignal(str, str, int)

    def __init__(self, raw):
        super().__init__()
        self._raw = raw

    def run(self):
        mode, extracted, count = detect_and_extract(self._raw)
        self.finished.emit(mode, extracted, count)


class ProcessWorker(QThread):
    finished = pyqtSignal(str)

    def __init__(self, op, text, mode, **kwargs):
        super().__init__()
        self._op   = op
        self._text = text
        self._mode = mode
        self._kw   = kwargs

    def run(self):
        try:
            if self._op == "sni":
                if self._mode == "json":
                    result = transform_json_configs(
                        self._text,
                        self._kw.get("minimal_mode", False),
                        self._kw.get("insecure_mode", False)
                    )
                else:
                    result = process_sni_spoof(
                        self._text,
                        self._kw.get("minimal_mode", False),
                        self._kw.get("insecure_mode", False)
                    )
            elif self._op == "ip":
                result = process_simple(self._text, new_host=self._kw.get("host"))
            elif self._op == "port":
                result = process_simple(self._text, new_port=self._kw.get("port"))
            elif self._op == "both":
                result = process_simple(
                    self._text,
                    new_host=self._kw.get("host"),
                    new_port=self._kw.get("port")
                )
            else:
                result = self._text
        except Exception as e:
            result = f"[Error] {e}"
        self.finished.emit(result)


# ---------------------------------------------------------------------------
# UI components
# ---------------------------------------------------------------------------

class GradientButton(QPushButton):
    def __init__(self, text, color1=ACCENT, color2=ACCENT2, parent=None):
        super().__init__(text, parent)
        self.color1   = color1
        self.color2   = color2
        self._hovered = False
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setFixedHeight(44)
        self.setFont(QFont("JetBrains Mono", 11, QFont.Medium))

    def enterEvent(self, e):
        self._hovered = True
        self.update()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._hovered = False
        self.update()
        super().leaveEvent(e)

    def paintEvent(self, _):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.rect()
        c1   = QColor(self.color1)
        c2   = QColor(self.color2)
        if self._hovered:
            c1 = c1.lighter(115)
            c2 = c2.lighter(115)
        grad = QLinearGradient(rect.topLeft(), rect.topRight())
        grad.setColorAt(0, c1)
        grad.setColorAt(1, c2)
        painter.setBrush(grad)
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(rect, 10, 10)
        painter.setPen(QColor("#ffffff"))
        painter.setFont(self.font())
        painter.drawText(rect, Qt.AlignCenter, self.text())


class OptionButton(QPushButton):
    def __init__(self, number, title, desc, active_color=ACCENT, parent=None):
        super().__init__(parent)
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setFixedHeight(76)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._number       = number
        self._title        = title
        self._desc         = desc
        self._active_color = active_color
        self._hovered      = False
        self._active       = False

    def set_active(self, v):
        self._active = v
        self.update()

    def enterEvent(self, e):
        self._hovered = True
        self.update()
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._hovered = False
        self.update()
        super().leaveEvent(e)

    def paintEvent(self, _):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect   = self.rect()
        on     = self._hovered or self._active
        bg     = QColor("#1e1e2e") if on else QColor(CARD_BG)
        border = QColor(self._active_color) if on else QColor(BORDER)
        painter.setBrush(bg)
        painter.setPen(border)
        painter.drawRoundedRect(rect.adjusted(1, 1, -1, -1), 10, 10)

        bw    = 30
        badge = QRect(14, (rect.height() - bw) // 2, bw, bw)
        grad  = QLinearGradient(badge.topLeft(), badge.bottomRight())
        grad.setColorAt(0, QColor(self._active_color))
        grad.setColorAt(1, QColor(ACCENT2))
        painter.setBrush(grad)
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(badge, 7, 7)

        painter.setPen(QColor("#ffffff"))
        painter.setFont(QFont("JetBrains Mono", 10, QFont.Bold))
        painter.drawText(badge, Qt.AlignCenter, str(self._number))

        painter.setPen(QColor(TEXT_PRI))
        painter.setFont(QFont("JetBrains Mono", 12, QFont.Medium))
        painter.drawText(QRect(56, 14, rect.width() - 70, 22),
                         Qt.AlignLeft | Qt.AlignVCenter, self._title)

        painter.setPen(QColor(TEXT_SEC))
        painter.setFont(QFont("JetBrains Mono", 9))
        painter.drawText(QRect(56, 38, rect.width() - 70, 18),
                         Qt.AlignLeft | Qt.AlignVCenter, self._desc)


class TagLabel(QLabel):
    def __init__(self, text, color=ACCENT, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont("JetBrains Mono", 8, QFont.Bold))
        self.setStyleSheet(
            f"color:{color}; background:{color}22; border:1px solid {color}44;"
            f"border-radius:4px; padding:2px 7px; letter-spacing:1px;"
        )
        self.setFixedHeight(20)


class SectionLabel(QLabel):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setFont(QFont("JetBrains Mono", 9, QFont.Bold))
        self.setStyleSheet(f"color:{TEXT_MUTED}; letter-spacing:2px;")


class Divider(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.HLine)
        self.setStyleSheet(f"background:{BORDER}; border:none;")
        self.setFixedHeight(1)


class StatusDot(QWidget):
    def __init__(self, color=SUCCESS, parent=None):
        super().__init__(parent)
        self._color = color
        self.setFixedSize(8, 8)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor(self._color))
        p.setPen(Qt.NoPen)
        p.drawEllipse(0, 0, 8, 8)


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("V2ray Config Editor")
        self.setMinimumSize(980, 740)
        self.resize(1140, 800)
        self.setStyleSheet(STYLESHEET)

        self._input_text   = ""
        self._input_mode   = "unknown"
        self._current_op   = None

        self._extract_worker = None
        self._process_worker = None

        self._debounce = QTimer()
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(450)
        self._debounce.timeout.connect(self._run_extract)

        self._build_ui()

    # ------------------------------------------------------------------
    # Layout builders
    # ------------------------------------------------------------------

    def _build_ui(self):
        root = QWidget()
        root.setObjectName("root")
        root.setStyleSheet(f"background-color:{DARK_BG};")
        self.setCentralWidget(root)
        row = QHBoxLayout(root)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        row.addWidget(self._build_sidebar())
        row.addWidget(self._build_content(), 1)

    def _build_sidebar(self):
        sb  = QWidget()
        sb.setFixedWidth(292)
        sb.setStyleSheet(f"background-color:{PANEL_BG}; border-right:1px solid {BORDER};")
        lay = QVBoxLayout(sb)
        lay.setContentsMargins(22, 30, 22, 22)
        lay.setSpacing(0)

        logo_row = QHBoxLayout()
        logo_row.addWidget(StatusDot(ACCENT))
        logo_row.addSpacing(8)
        lbl = QLabel("V2RAY EDITOR")
        lbl.setFont(QFont("JetBrains Mono", 13, QFont.Bold))
        lbl.setStyleSheet(f"color:{TEXT_PRI}; letter-spacing:1px;")
        logo_row.addWidget(lbl)
        logo_row.addStretch()
        lay.addLayout(logo_row)
        lay.addSpacing(4)

        sub = QLabel("Bulk Config Transformer")
        sub.setFont(QFont("JetBrains Mono", 9))
        sub.setStyleSheet(f"color:{TEXT_MUTED};")
        lay.addWidget(sub)
        lay.addSpacing(28)

        lay.addWidget(SectionLabel("OPERATIONS"))
        lay.addSpacing(10)

        self.btn_sni = OptionButton(1, "SNI Spoof  →  127.0.0.1:40443",
                                    "Full transform: TLS · SNI · ECH strip",
                                    active_color=ACCENT)
        self.btn_op2 = OptionButton(2, "Replace IP Only",
                                    "Custom host address",
                                    active_color="#3b82f6")
        self.btn_op3 = OptionButton(3, "Replace Port Only",
                                    "Custom port number",
                                    active_color="#3b82f6")
        self.btn_op4 = OptionButton(4, "Replace IP + Port",
                                    "Simple host:port swap",
                                    active_color="#3b82f6")

        self.btn_sni.clicked.connect(lambda: self._on_option(1))
        self.btn_op2.clicked.connect(lambda: self._on_option(2))
        self.btn_op3.clicked.connect(lambda: self._on_option(3))
        self.btn_op4.clicked.connect(lambda: self._on_option(4))

        for b in (self.btn_sni, self.btn_op2, self.btn_op3, self.btn_op4):
            lay.addWidget(b)
            lay.addSpacing(7)

        lay.addSpacing(10)
        lay.addWidget(Divider())
        lay.addSpacing(14)

        lay.addWidget(SectionLabel("SNI SPOOF OPTIONS"))
        lay.addSpacing(10)

        self.chk_minimal    = QCheckBox("Minimal Mode  (path → /)")
        self.chk_insecure   = QCheckBox("Insecure Mode  (allowInsecure=1)")
        self.chk_export_b64 = QCheckBox("Export as Base64  (subscription)")
        self.chk_minimal.setStyleSheet(f"color:{TEXT_SEC}; font-size:11px;")
        self.chk_insecure.setStyleSheet(f"color:{WARNING}; font-size:11px;")
        self.chk_export_b64.setStyleSheet(f"color:{ACCENT2}; font-size:11px;")
        lay.addWidget(self.chk_minimal)
        lay.addSpacing(6)
        lay.addWidget(self.chk_insecure)
        lay.addSpacing(6)
        lay.addWidget(self.chk_export_b64)

        lay.addStretch()

        self.status_label = QLabel("Waiting for input…")
        self.status_label.setFont(QFont("JetBrains Mono", 9))
        self.status_label.setStyleSheet(f"color:{TEXT_MUTED};")
        self.status_label.setWordWrap(True)
        lay.addWidget(self.status_label)
        lay.addSpacing(6)

        ver = QLabel("v3.0  ·  URL · JSON · Base64")
        ver.setFont(QFont("JetBrains Mono", 8))
        ver.setStyleSheet(f"color:{TEXT_MUTED};")
        lay.addWidget(ver)
        return sb

    def _build_content(self):
        c   = QWidget()
        c.setStyleSheet(f"background-color:{DARK_BG};")
        lay = QVBoxLayout(c)
        lay.setContentsMargins(32, 30, 32, 28)
        lay.setSpacing(0)

        title_row = QHBoxLayout()
        hdr = QLabel("Paste your configs")
        hdr.setFont(QFont("JetBrains Mono", 19, QFont.Bold))
        hdr.setStyleSheet(f"color:{TEXT_PRI};")
        title_row.addWidget(hdr)
        title_row.addStretch()

        self.tag_url  = TagLabel("URL",  SUCCESS)
        self.tag_json = TagLabel("JSON", "#f59e0b")
        self.tag_b64  = TagLabel("BASE64", ACCENT2)
        for t in (self.tag_url, self.tag_json, self.tag_b64):
            t.setVisible(False)
            title_row.addWidget(t)
            title_row.addSpacing(6)
        lay.addLayout(title_row)
        lay.addSpacing(4)

        hint = QLabel(
            "URL  ·  JSON (Xray full config)  ·  Base64 subscription  ·  mixed input"
        )
        hint.setFont(QFont("JetBrains Mono", 9))
        hint.setStyleSheet(f"color:{TEXT_MUTED};")
        lay.addWidget(hint)
        lay.addSpacing(20)

        lay.addWidget(SectionLabel("INPUT"))
        lay.addSpacing(8)

        self.input_area = QTextEdit()
        self.input_area.setPlaceholderText(
            "vless://uuid@domain.workers.dev:80?security=none&...\n"
            "— or paste a full Xray JSON config / Base64 subscription —"
        )
        self.input_area.setMinimumHeight(195)
        self.input_area.textChanged.connect(self._on_input_changed)
        lay.addWidget(self.input_area)

        lay.addSpacing(20)
        lay.addWidget(Divider())
        lay.addSpacing(18)

        out_hdr = QHBoxLayout()
        ol = QLabel("OUTPUT")
        ol.setFont(QFont("JetBrains Mono", 9, QFont.Bold))
        ol.setStyleSheet(f"color:{TEXT_MUTED}; letter-spacing:2px;")
        out_hdr.addWidget(ol)
        out_hdr.addStretch()
        self.stats_label = QLabel("")
        self.stats_label.setFont(QFont("JetBrains Mono", 9))
        self.stats_label.setStyleSheet(f"color:{TEXT_MUTED};")
        out_hdr.addWidget(self.stats_label)
        out_hdr.addSpacing(14)
        self.copy_btn = GradientButton("  Copy to Clipboard", ACCENT, ACCENT2)
        self.copy_btn.setFixedWidth(186)
        self.copy_btn.clicked.connect(self._copy_output)
        out_hdr.addWidget(self.copy_btn)
        lay.addLayout(out_hdr)
        lay.addSpacing(8)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.output_area.setPlaceholderText("Transformed configs will appear here…")
        self.output_area.setMinimumHeight(195)
        lay.addWidget(self.output_area)

        lay.addSpacing(14)

        self.custom_row = QWidget()
        cr  = QHBoxLayout(self.custom_row)
        cr.setContentsMargins(0, 0, 0, 0)
        cr.setSpacing(10)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("New IP / hostname")
        self.ip_input.setVisible(False)
        self.ip_input.returnPressed.connect(self._apply_custom)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("New port  (e.g. 8443)")
        self.port_input.setVisible(False)
        self.port_input.returnPressed.connect(self._apply_custom)

        self.apply_btn = GradientButton("Apply", SUCCESS, "#16a085")
        self.apply_btn.setFixedWidth(100)
        self.apply_btn.setVisible(False)
        self.apply_btn.clicked.connect(self._apply_custom)

        cr.addWidget(self.ip_input)
        cr.addWidget(self.port_input)
        cr.addWidget(self.apply_btn)
        lay.addWidget(self.custom_row)
        return c

    # ------------------------------------------------------------------
    # Input pipeline (debounced → background worker)
    # ------------------------------------------------------------------

    def _on_input_changed(self):
        self.status_label.setText("Parsing…")
        self.status_label.setStyleSheet(f"color:{TEXT_MUTED};")
        self._debounce.start()

    def _run_extract(self):
        raw = self.input_area.toPlainText()
        if not raw.strip():
            self._input_text = ""
            self._input_mode = "unknown"
            self._update_tags("unknown")
            self.status_label.setText("Waiting for input…")
            self.status_label.setStyleSheet(f"color:{TEXT_MUTED};")
            return
        if self._extract_worker and self._extract_worker.isRunning():
            self._extract_worker.finished.disconnect()
            self._extract_worker.quit()
            self._extract_worker.wait(300)
        self._extract_worker = ExtractWorker(raw)
        self._extract_worker.finished.connect(self._on_extract_done)
        self._extract_worker.start()

    def _on_extract_done(self, mode, extracted, count):
        self._input_text = extracted
        self._input_mode = mode
        self._update_tags(mode)
        if count > 0:
            labels = {"url": "URL", "json": "JSON", "b64": "Base64"}
            suffix = f"  [{labels.get(mode, '')}]" if mode in labels else ""
            self.status_label.setText(f"{count} config(s) detected{suffix}")
            self.status_label.setStyleSheet(f"color:{SUCCESS};")
        else:
            self.status_label.setText("No valid V2ray configs found")
            self.status_label.setStyleSheet(f"color:{WARNING};")

    def _update_tags(self, mode):
        self.tag_url.setVisible(mode == "url")
        self.tag_json.setVisible(mode == "json")
        self.tag_b64.setVisible(mode == "b64")

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------

    def _all_btns(self):
        return [self.btn_sni, self.btn_op2, self.btn_op3, self.btn_op4]

    def _guard(self):
        if not self._input_text.strip():
            self.status_label.setText("Paste configs first")
            self.status_label.setStyleSheet(f"color:{WARNING};")
            return False
        if self._input_mode == "unknown":
            self.status_label.setText("No valid V2ray configs found")
            self.status_label.setStyleSheet(f"color:{WARNING};")
            return False
        return True

    def _on_option(self, op):
        if not self._guard():
            return
        self._current_op = op
        for b in self._all_btns():
            b.set_active(False)
        self._all_btns()[op - 1].set_active(True)

        self.ip_input.setVisible(False)
        self.port_input.setVisible(False)
        self.apply_btn.setVisible(False)

        if op == 1:
            self._run_process("sni",
                              minimal_mode=self.chk_minimal.isChecked(),
                              insecure_mode=self.chk_insecure.isChecked())
        elif op == 2:
            self.ip_input.setVisible(True)
            self.apply_btn.setVisible(True)
            self.ip_input.setFocus()
        elif op == 3:
            self.port_input.setVisible(True)
            self.apply_btn.setVisible(True)
            self.port_input.setFocus()
        elif op == 4:
            self.ip_input.setVisible(True)
            self.port_input.setVisible(True)
            self.apply_btn.setVisible(True)
            self.ip_input.setFocus()

    def _apply_custom(self):
        op = self._current_op
        h  = self.ip_input.text().strip()
        p  = self.port_input.text().strip()
        if op == 2:
            if not h:
                return
            self._run_process("ip", host=h)
        elif op == 3:
            if not p:
                return
            self._run_process("port", port=p)
        elif op == 4:
            if not h and not p:
                return
            self._run_process("both", host=h or None, port=p or None)

    def _run_process(self, op, **kwargs):
        if self._process_worker and self._process_worker.isRunning():
            self._process_worker.finished.disconnect()
            self._process_worker.quit()
            self._process_worker.wait(300)
        self.status_label.setText("Processing…")
        self.status_label.setStyleSheet(f"color:{TEXT_MUTED};")
        self._process_worker = ProcessWorker(
            op, self._input_text, self._input_mode, **kwargs
        )
        self._process_worker.finished.connect(
            lambda result: self._on_process_done(result, op, kwargs)
        )
        self._process_worker.start()

    def _on_process_done(self, result, op, kwargs):
        labels = {
            "sni":  "SNI Spoof applied → 127.0.0.1:40443",
            "ip":   f"IP replaced → {kwargs.get('host', '')}",
            "port": f"Port replaced → {kwargs.get('port', '')}",
            "both": f"Replaced → {kwargs.get('host','(same)')}:{kwargs.get('port','(same)')}",
        }
        self._show_output(result, labels.get(op, "Done"))

    def _show_output(self, text, status_msg):
        if self.chk_export_b64.isChecked() and text.strip():
            display = export_base64(text)
            suffix  = "  →  Base64"
        else:
            display = text
            suffix  = ""

        self.output_area.setPlainText(display)

        if self._input_mode == "json":
            try:
                data = json.loads(text)
                n = len(data) if isinstance(data, list) else 1
            except Exception:
                n = 0
        else:
            n = len([l for l in text.splitlines() if l.strip()])

        self.stats_label.setText(f"{n} configs")

        if display.strip():
            QApplication.clipboard().setText(display)

        self.status_label.setText(status_msg + suffix + "  ·  copied")
        self.status_label.setStyleSheet(f"color:{SUCCESS};")

    def _copy_output(self):
        text = self.output_area.toPlainText()
        if text.strip():
            QApplication.clipboard().setText(text)
            orig = self.copy_btn.text()
            self.copy_btn.setText("  Copied!")
            QTimer.singleShot(1800, lambda: self.copy_btn.setText(orig))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.Window,      QColor(DARK_BG))
    pal.setColor(QPalette.WindowText,  QColor(TEXT_PRI))
    pal.setColor(QPalette.Base,        QColor(CARD_BG))
    pal.setColor(QPalette.AlternateBase, QColor(PANEL_BG))
    pal.setColor(QPalette.Text,        QColor(TEXT_PRI))
    pal.setColor(QPalette.Button,      QColor(PANEL_BG))
    pal.setColor(QPalette.ButtonText,  QColor(TEXT_PRI))
    app.setPalette(pal)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
