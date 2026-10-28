"""Тёмная тема в стиле Windows 11 / Fluent."""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap

from core.models import OverallStatus

BG = "#1c1c1c"
SIDEBAR = "#202020"
SURFACE = "#2b2b2b"
SURFACE_2 = "#323232"
SURFACE_HOVER = "#3a3a3a"
BORDER = "#3d3d3d"
TEXT = "#ffffff"
TEXT_2 = "#d0d0d0"
MUTED = "#9d9d9d"
ACCENT = "#60cdff"
ACCENT_TEXT = "#000000"

GREEN = "#6ccb5f"
YELLOW = "#fce100"
RED = "#ff6b78"
GRAY = "#8a8a8a"

GREEN_BG = "#1f3a1c"
YELLOW_BG = "#433519"
RED_BG = "#4a2228"
GRAY_BG = "#2e2e2e"

STATUS_COLORS = {
    OverallStatus.NO_CONNECTIONS: (GREEN, GREEN_BG),
    OverallStatus.INSUFFICIENT: (YELLOW, YELLOW_BG),
    OverallStatus.CONNECTED: (RED, RED_BG),
    OverallStatus.STOPPED: (GRAY, GRAY_BG),
}

FONT_FAMILY = "Segoe UI Variable Text, Segoe UI, Arial"

from app.config import resource_path  # noqa: E402

CHECK_PNG = resource_path("assets/icons/check.png").as_posix()


def app_font() -> QFont:
    f = QFont()
    f.setFamilies(["Segoe UI Variable Text", "Segoe UI", "Arial"])
    f.setPointSizeF(10)
    return f


QSS = f"""
* {{ font-family: {FONT_FAMILY}; }}
QWidget {{ background: {BG}; color: {TEXT}; font-size: 10pt; }}
QMainWindow, #Root {{ background: {BG}; }}
QToolTip {{ background: {SURFACE_2}; color: {TEXT}; border: 1px solid {BORDER}; padding: 6px; border-radius: 6px; }}

#Sidebar {{ background: {SIDEBAR}; border-right: 1px solid #2a2a2a; }}
#Sidebar QPushButton {{
    background: transparent; border: none; border-radius: 6px; text-align: left;
    padding: 9px 12px 9px 14px; color: {TEXT_2}; font-size: 10pt;
}}
#Sidebar QPushButton:hover {{ background: {SURFACE}; color: {TEXT}; }}
#Sidebar QPushButton:checked {{ background: {SURFACE_2}; color: {TEXT}; border-left: 3px solid {ACCENT}; padding-left: 11px; }}
#AppTitle {{ font-size: 15pt; font-weight: 600; background: transparent; }}
#AppSubtitle {{ color: {MUTED}; background: transparent; }}
#PageTitle {{ font-size: 18pt; font-weight: 600; background: transparent; }}
#PageSubtitle {{ color: {MUTED}; background: transparent; }}
#SysInfo {{ color: {MUTED}; font-size: 9pt; background: transparent; }}

#Card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 10px; }}
#Card QLabel {{ background: transparent; }}
#CardTitle {{ color: {MUTED}; font-size: 9pt; }}
#CardValue {{ font-size: 20pt; font-weight: 600; }}
#CardHint {{ color: {MUTED}; font-size: 9pt; }}
#SectionTitle {{ font-size: 12pt; font-weight: 600; background: transparent; margin-top: 6px; }}
#Muted {{ color: {MUTED}; background: transparent; }}
#Footnote {{ color: {MUTED}; font-size: 9pt; background: transparent; }}

QPushButton {{
    background: {SURFACE_2}; border: 1px solid {BORDER}; border-radius: 6px; padding: 6px 14px; color: {TEXT};
}}
QPushButton:hover {{ background: {SURFACE_HOVER}; }}
QPushButton:pressed {{ background: {SURFACE}; color: {TEXT_2}; }}
QPushButton:disabled {{ color: #6a6a6a; }}
QPushButton#Primary {{ background: {ACCENT}; color: {ACCENT_TEXT}; border: 1px solid {ACCENT}; font-weight: 600; }}
QPushButton#Primary:hover {{ background: #7ad6ff; }}
QPushButton#Danger {{ color: {RED}; }}

QLineEdit, QSpinBox, QComboBox, QDateTimeEdit {{
    background: {SURFACE_2}; border: 1px solid {BORDER}; border-bottom: 1px solid #8a8a8a;
    border-radius: 6px; padding: 5px 8px; selection-background-color: {ACCENT}; selection-color: #000;
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{ border-bottom: 2px solid {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background: {SURFACE_2}; border: 1px solid {BORDER}; selection-background-color: {SURFACE_HOVER}; }}
QSpinBox::up-button, QSpinBox::down-button {{ width: 16px; border: none; background: transparent; }}

QCheckBox {{ spacing: 8px; background: transparent; }}
QCheckBox::indicator {{ width: 18px; height: 18px; border-radius: 4px; border: 1px solid #8a8a8a; background: {SURFACE_2}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border: 1px solid {ACCENT}; image: url("{CHECK_PNG}"); }}
QCheckBox::indicator:disabled {{ background: #2a2a2a; border: 1px solid #555; }}

QTableView {{
    background: {SURFACE}; alternate-background-color: #2f2f2f; border: 1px solid {BORDER}; border-radius: 10px;
    gridline-color: transparent; selection-background-color: #3f4d57; selection-color: {TEXT};
}}
QTableView::item {{ padding: 4px 8px; border: none; }}
QHeaderView {{ background: transparent; }}
QHeaderView::section {{
    background: {SURFACE}; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER};
    padding: 7px 8px; font-weight: 600;
}}
QTableCornerButton::section {{ background: {SURFACE}; border: none; }}

QScrollArea {{ border: none; background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #5a5a5a; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: #7a7a7a; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: #5a5a5a; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

QTextBrowser, QPlainTextEdit {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 8px; padding: 6px; }}
QMenu {{ background: {SURFACE_2}; border: 1px solid {BORDER}; border-radius: 8px; padding: 4px; }}
QMenu::item {{ padding: 6px 24px 6px 14px; border-radius: 4px; }}
QMenu::item:selected {{ background: {SURFACE_HOVER}; }}
QMenu::separator {{ height: 1px; background: {BORDER}; margin: 4px 8px; }}
QSplitter::handle {{ background: transparent; }}
"""


def rgba(hex_color: str, alpha: float) -> str:
    """'#rrggbb' + прозрачность 0..1 → строка rgba() для QSS (Qt читает #AARRGGBB, а не #RRGGBBAA)."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r}, {g}, {b}, {int(alpha * 255)})"


def status_icon(status: OverallStatus, size: int = 64) -> QIcon:
    """Значок трея: тёмный щит с цветным индикатором состояния."""
    color = QColor(STATUS_COLORS[status][0])
    icon = QIcon()
    for s in (16, 20, 24, 32, 48, size):
        pm = QPixmap(s, s)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.Antialiasing)
        # монитор
        r = QRectF(s * 0.06, s * 0.12, s * 0.88, s * 0.62)
        p.setPen(QPen(QColor("#e8e8e8"), max(1.0, s * 0.06)))
        p.setBrush(QBrush(QColor("#2b2b2b")))
        p.drawRoundedRect(r, s * 0.1, s * 0.1)
        p.drawLine(QPointF(s * 0.5, s * 0.74), QPointF(s * 0.5, s * 0.86))
        p.drawLine(QPointF(s * 0.3, s * 0.88), QPointF(s * 0.7, s * 0.88))
        # индикатор
        d = s * 0.42
        p.setPen(QPen(QColor("#1c1c1c"), max(1.0, s * 0.05)))
        p.setBrush(QBrush(color))
        p.drawEllipse(QRectF(s - d - s * 0.02, s - d - s * 0.02, d, d))
        p.end()
        icon.addPixmap(pm)
    return icon


def dot_pixmap(color: str, size: int = 14) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor(color))
    p.drawEllipse(QRectF(1, 1, size - 2, size - 2))
    p.end()
    return pm


def nav_icon(kind: str, size: int = 20, color: str = TEXT_2) -> QIcon:
    """Простые векторные значки навигации (без внешних ресурсов)."""
    pm = QPixmap(size * 2, size * 2)
    pm.fill(Qt.transparent)
    s = size * 2
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    pen = QPen(QColor(color), s * 0.07, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    if kind == "dashboard":
        for x, y, w, h in ((0.15, 0.15, 0.3, 0.4), (0.55, 0.15, 0.3, 0.25), (0.15, 0.6, 0.3, 0.25), (0.55, 0.45, 0.3, 0.4)):
            p.drawRoundedRect(QRectF(s * x, s * y, s * w, s * h), s * 0.05, s * 0.05)
    elif kind == "sessions":
        p.drawRoundedRect(QRectF(s * 0.12, s * 0.18, s * 0.76, s * 0.5), s * 0.06, s * 0.06)
        p.drawLine(QPointF(s * 0.5, s * 0.68), QPointF(s * 0.5, s * 0.8))
        p.drawLine(QPointF(s * 0.32, s * 0.82), QPointF(s * 0.68, s * 0.82))
    elif kind == "history":
        p.drawEllipse(QRectF(s * 0.15, s * 0.15, s * 0.7, s * 0.7))
        p.drawLine(QPointF(s * 0.5, s * 0.3), QPointF(s * 0.5, s * 0.5))
        p.drawLine(QPointF(s * 0.5, s * 0.5), QPointF(s * 0.65, s * 0.6))
    elif kind == "tools":
        path = QPainterPath()
        path.moveTo(s * 0.2, s * 0.8)
        path.lineTo(s * 0.55, s * 0.45)
        p.drawPath(path)
        p.drawEllipse(QRectF(s * 0.5, s * 0.15, s * 0.32, s * 0.32))
    elif kind == "diagnostics":
        path = QPainterPath()
        path.moveTo(s * 0.1, s * 0.55)
        path.lineTo(s * 0.32, s * 0.55)
        path.lineTo(s * 0.42, s * 0.3)
        path.lineTo(s * 0.56, s * 0.75)
        path.lineTo(s * 0.66, s * 0.5)
        path.lineTo(s * 0.9, s * 0.5)
        p.drawPath(path)
    elif kind == "settings":
        p.drawEllipse(QRectF(s * 0.36, s * 0.36, s * 0.28, s * 0.28))
        p.drawEllipse(QRectF(s * 0.18, s * 0.18, s * 0.64, s * 0.64))
    p.end()
    return QIcon(pm)
