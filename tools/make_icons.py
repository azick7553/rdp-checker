"""Генерация assets/icons/app.ico и check.png (запускать при изменении дизайна значков).

    QT_QPA_PLATFORM=offscreen python tools/make_icons.py
"""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PIL import Image  # noqa: E402
from PySide6.QtCore import QBuffer, QIODevice, QPointF, Qt  # noqa: E402
from PySide6.QtGui import QColor, QGuiApplication, QImage, QPainter, QPen  # noqa: E402

from core.models import OverallStatus  # noqa: E402
from gui import theme  # noqa: E402


def qimage_to_pil(img: QImage) -> Image.Image:
    buf = QBuffer()
    buf.open(QIODevice.WriteOnly)
    img.save(buf, "PNG")
    return Image.open(io.BytesIO(bytes(buf.data()))).convert("RGBA")


def main() -> None:
    app = QGuiApplication([])  # noqa: F841
    out = ROOT / "assets" / "icons"
    out.mkdir(parents=True, exist_ok=True)
    icon = theme.status_icon(OverallStatus.NO_CONNECTIONS, 256)
    big = qimage_to_pil(icon.pixmap(256, 256).toImage())
    big.save(out / "app.ico", sizes=[(16, 16), (20, 20), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    big.save(out / "app.png")

    for scale, name in ((1, "check.png"), (2, "check@2x.png")):
        img = QImage(18 * scale, 18 * scale, QImage.Format_ARGB32)
        img.fill(Qt.transparent)
        p = QPainter(img)
        p.setRenderHint(QPainter.Antialiasing)
        p.scale(scale, scale)
        p.setPen(QPen(QColor("#000000"), 2.0, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        p.drawPolyline([QPointF(4, 9.5), QPointF(7.3, 12.8), QPointF(14, 5.8)])
        p.end()
        img.save(str(out / name))
    print("icons written to", out)


if __name__ == "__main__":
    main()
