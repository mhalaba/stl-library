#!/usr/bin/env python3
"""Fill the library with a few sample models, to see the thing working.

    ./.venv/bin/python tools/seed_demo.py

Generates a handful of simple solids as binary STL files, puts them in the
library and - if a private key is present in the environment (online mode) -
signs them straight away. Delete this once you upload your own models.
"""

import math
import os
import struct
import sys
import time
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db, integrity, storage  # noqa: E402


def write_stl(triangles):
    out = BytesIO()
    out.write(b"\0" * 80)
    out.write(struct.pack("<I", len(triangles)))
    for a, b, c in triangles:
        ux, uy, uz = (b[0] - a[0], b[1] - a[1], b[2] - a[2])
        vx, vy, vz = (c[0] - a[0], c[1] - a[1], c[2] - a[2])
        nx, ny, nz = (uy * vz - uz * vy, uz * vx - ux * vz, ux * vy - uy * vx)
        length = math.sqrt(nx * nx + ny * ny + nz * nz) or 1.0
        out.write(struct.pack("<fff", nx / length, ny / length, nz / length))
        for point in (a, b, c):
            out.write(struct.pack("<fff", *point))
        out.write(struct.pack("<H", 0))
    out.seek(0)
    return out


def quad(triangles, p1, p2, p3, p4):
    triangles.append((p1, p2, p3))
    triangles.append((p1, p3, p4))


def torus(radius=20.0, tube=7.0, segments=64, sides=32):
    triangles = []
    for i in range(segments):
        for j in range(sides):
            def point(di, dj):
                u = 2 * math.pi * ((i + di) % segments) / segments
                v = 2 * math.pi * ((j + dj) % sides) / sides
                r = radius + tube * math.cos(v)
                return (r * math.cos(u), r * math.sin(u), tube * math.sin(v))
            quad(triangles, point(0, 0), point(1, 0), point(1, 1), point(0, 1))
    return triangles


def gear(teeth=14, radius=22.0, tooth=5.0, thickness=8.0, bore=6.0):
    triangles = []
    steps = teeth * 4
    outline = []
    for i in range(steps):
        angle = 2 * math.pi * i / steps
        r = radius + (tooth if (i % 4) < 2 else 0)
        outline.append((r * math.cos(angle), r * math.sin(angle)))
    inner = [(bore * math.cos(2 * math.pi * i / steps), bore * math.sin(2 * math.pi * i / steps))
             for i in range(steps)]

    for i in range(steps):
        a, b = outline[i], outline[(i + 1) % steps]
        ia, ib = inner[i], inner[(i + 1) % steps]
        for z in (0.0, thickness):
            quad(triangles, (ia[0], ia[1], z), (a[0], a[1], z), (b[0], b[1], z), (ib[0], ib[1], z))
        quad(triangles, (a[0], a[1], 0), (a[0], a[1], thickness),
             (b[0], b[1], thickness), (b[0], b[1], 0))
        quad(triangles, (ib[0], ib[1], 0), (ib[0], ib[1], thickness),
             (ia[0], ia[1], thickness), (ia[0], ia[1], 0))
    return triangles


def hook(width=30.0, height=45.0, depth=12.0, plate=4.0):
    triangles = []

    def box(x0, y0, z0, x1, y1, z1):
        corners = [
            ((x0, y0, z0), (x1, y0, z0), (x1, y1, z0), (x0, y1, z0)),
            ((x0, y0, z1), (x0, y1, z1), (x1, y1, z1), (x1, y0, z1)),
            ((x0, y0, z0), (x0, y0, z1), (x1, y0, z1), (x1, y0, z0)),
            ((x1, y0, z0), (x1, y0, z1), (x1, y1, z1), (x1, y1, z0)),
            ((x1, y1, z0), (x1, y1, z1), (x0, y1, z1), (x0, y1, z0)),
            ((x0, y1, z0), (x0, y1, z1), (x0, y0, z1), (x0, y0, z0)),
        ]
        for face in corners:
            quad(triangles, *face)

    box(0, 0, 0, width, height, plate)                       # back plate
    box(0, 0, 0, width, plate, depth)                        # arm
    box(0, 0, depth - plate, width, plate * 3, depth)        # upturned tip
    return triangles


MODELS = [
    ("Calibration ring", "calibration-ring",
     "A torus for extruder calibration. Prints without supports, 0.2 mm layers.",
     "calibration", torus()),
    ("Spur gear M2 z14", "spur-gear-m2-z14",
     "Plain spur gear, module 2, 14 teeth, 6 mm bore.",
     "mechanical", gear()),
    ("Wall hook", "wall-hook",
     "Wall-mounted hook, two screw holes. PETG, 30% infill.",
     "accessories", hook()),
]


def main() -> int:
    db.init()
    admin = db.query_one("SELECT id FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1")
    if admin is None:
        print("Create an administrator account first (STL_ADMIN_EMAIL / STL_ADMIN_PASSWORD).")
        return 1

    for title, slug, description, category, triangles in MODELS:
        if db.query_one("SELECT id FROM models WHERE slug = ?", (slug,)):
            print("skipping (already present): {}".format(slug))
            continue

        model_id = db.execute(
            "INSERT INTO models (slug, title, description, category, license, is_published, "
            "created_at, created_by) VALUES (?, ?, ?, ?, 'CC BY-NC 4.0', 1, ?, ?)",
            (slug, title, description, category, int(time.time()), admin["id"]),
        )

        data = write_stl(triangles)
        sha256_hex, size, count, relative, _ = storage.store_upload(data, 256 * 1024 * 1024)
        file_id = db.execute(
            "INSERT INTO files (model_id, filename, size, sha256, storage_path, triangles, "
            "status, uploaded_at, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
            (model_id, slug + ".stl", size, sha256_hex, relative, count, int(time.time()), admin["id"]),
        )

        row = db.query_one("SELECT * FROM files WHERE id = ?", (file_id,))
        signed, note = integrity.sign_file_row(row, slug)
        print("{:22} {} triangles  sha256={}  {}".format(
            slug, count, sha256_hex[:16], "signed" if signed else note))

    return 0


if __name__ == "__main__":
    sys.exit(main())
