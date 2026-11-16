#!/usr/bin/env python3
"""Gera windows/icone.ico a partir de icone.svg. Rodar no Linux (usa o GdkPixbuf):

    python3 windows/gerar_icone.py

Só é preciso repetir quando o icone.svg mudar.
"""
import os
import struct

import gi
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import GdkPixbuf  # noqa: E402

AQUI = os.path.dirname(os.path.abspath(__file__))
SVG = os.path.join(AQUI, os.pardir, "icone.svg")
TAMANHOS = (16, 20, 24, 32, 40, 48, 64, 256)


def bitmap(pix) -> bytes:
    """Formato clássico dos ícones: BGRA de baixo para cima, seguido da máscara (vazia)."""
    size, stride, data = pix.get_width(), pix.get_rowstride(), pix.get_pixels()
    rows = []
    for y in reversed(range(size)):
        row = data[y * stride:y * stride + size * 4]
        rows.append(b"".join(bytes((row[i + 2], row[i + 1], row[i], row[i + 3]))
                             for i in range(0, size * 4, 4)))
    mask = bytes((size + 31) // 32 * 4) * size
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    return header + b"".join(rows) + mask


images = []
for size in TAMANHOS:
    pix = GdkPixbuf.Pixbuf.new_from_file_at_size(SVG, size, size)
    assert pix.get_n_channels() == 4 and pix.get_width() == pix.get_height() == size
    # 256 vai em PNG (aceito desde o Windows Vista); os menores, no formato clássico
    images.append((size, pix.save_to_bufferv("png", [], [])[1] if size >= 256 else bitmap(pix)))

offset = 6 + 16 * len(images)
ico = struct.pack("<HHH", 0, 1, len(images))
for size, blob in images:
    ico += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(blob), offset)
    offset += len(blob)
ico += b"".join(blob for _size, blob in images)

destino = os.path.join(AQUI, "icone.ico")
with open(destino, "wb") as fh:
    fh.write(ico)
print(f"{destino}: {len(images)} tamanhos, {len(ico)} bytes")
