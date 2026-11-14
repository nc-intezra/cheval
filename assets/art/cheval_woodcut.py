"""Build and render "cheval": a black horse rearing before its reflection in a cheval mirror,
in a woodcut style.

Runs in Blender 4.x and 5.x, with or without a UI:

    blender -b --factory-startup -P cheval_woodcut.py -- --out DIR [--frames N] [--res W H] [--samples S]

    # or from Blender's Python console (renders in a background Blender, the UI stays usable):
    exec(open(r"C:\\path\\cheval_woodcut.py").read())

Everything is generated: metaball horse, curve mane and tail, mirror, ground and sky. The look
comes from one emission-only "engraving" shader (lines whose width follows a simple lighting
term) plus inverted-hull outlines, so the reflection in the mirror is engraved and outlined too.
With --frames N > 1 the mane and tail blow in a seamless N-frame loop (frame_0000.png ...);
otherwise one still (cheval.png).
"""
import math
import os
import random
import sys

import bmesh
import bpy
from mathutils import Matrix, Quaternion, Vector

INK = (0.035, 0.03, 0.028, 1.0)
PAPER = (0.93, 0.895, 0.80, 1.0)
LIGHT = Vector((0.30, -0.55, 0.78)).normalized()  # high, from the viewer's side and ahead of the horse
HORSE_TURN = Matrix.Rotation(math.radians(22), 4, "Z")  # the horse turns toward the mirror


# ----------------------------------------------------------------------------- arguments
def parse_args():
    """Without --frames: a 1600x1000 still (cheval.png) and a 24-frame 800x500 loop
    (loop/frame_0000.png ...). With --frames N: only that, at --res."""
    argv = sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else []
    opts = {"out": None, "frames": None, "res": None, "samples": None}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--out":
            opts["out"] = argv[i + 1]; i += 2
        elif a == "--frames":
            opts["frames"] = int(argv[i + 1]); i += 2
        elif a == "--res":
            opts["res"] = (int(argv[i + 1]), int(argv[i + 2])); i += 3
        elif a == "--samples":
            opts["samples"] = int(argv[i + 1]); i += 2
        else:
            raise SystemExit(f"unknown argument {a}")
    if opts["out"] is None:
        opts["out"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "render")
    if opts["frames"] is None:
        jobs = [dict(out=opts["out"], frames=1, res=opts["res"] or (1600, 1000), samples=opts["samples"] or 48),
                dict(out=os.path.join(opts["out"], "loop"), frames=24, res=(800, 500), samples=opts["samples"] or 24)]
    else:
        jobs = [dict(out=opts["out"], frames=opts["frames"], res=opts["res"] or (1600, 1000),
                     samples=opts["samples"] or 32)]
    return jobs


# ----------------------------------------------------------------------------- materials
def _nodes(mat):
    if bpy.app.version < (5, 0, 0):  # always on, and deprecated, from Blender 5
        mat.use_nodes = True
    nt = mat.node_tree
    for n in list(nt.nodes):
        nt.nodes.remove(n)
    return nt


def engraving(name, albedo, ambient=0.0, scale=34.0, distortion=1.6, rotation=(0.0, 0.0, 0.0),
              direction="Z", coords="Object", gradient=None, detail=1.5):
    """Lines whose white share follows tone = albedo * (ambient + (1-ambient) * N.L).

    gradient: (axis, z0, z1, a0, a1) to vary the albedo along a world axis (sky)."""
    mat = bpy.data.materials.new(name)
    nt = _nodes(mat)
    N, L = nt.nodes, nt.links
    geo = N.new("ShaderNodeNewGeometry")
    tc = N.new("ShaderNodeTexCoord")
    mp = N.new("ShaderNodeMapping")
    mp.inputs["Rotation"].default_value = rotation
    L.new(tc.outputs[coords], mp.inputs["Vector"])
    wave = N.new("ShaderNodeTexWave")
    wave.wave_type = "BANDS"
    wave.bands_direction = direction
    wave.inputs["Scale"].default_value = scale
    wave.inputs["Distortion"].default_value = distortion
    wave.inputs["Detail"].default_value = detail
    L.new(mp.outputs["Vector"], wave.inputs["Vector"])

    dot = N.new("ShaderNodeVectorMath")
    dot.operation = "DOT_PRODUCT"
    dot.inputs[1].default_value = LIGHT
    L.new(geo.outputs["Normal"], dot.inputs[0])
    lam = N.new("ShaderNodeMath")
    lam.operation = "MAXIMUM"
    lam.inputs[1].default_value = 0.0
    L.new(dot.outputs["Value"], lam.inputs[0])
    shade = N.new("ShaderNodeMath")  # ambient + (1-ambient) * lambert
    shade.operation = "MULTIPLY_ADD"
    shade.inputs[1].default_value = 1.0 - ambient
    shade.inputs[2].default_value = ambient
    L.new(lam.outputs[0], shade.inputs[0])
    tone = N.new("ShaderNodeMath")
    tone.operation = "MULTIPLY"
    L.new(shade.outputs[0], tone.inputs[0])
    if gradient:
        axis, z0, z1, a0, a1 = gradient
        sep = N.new("ShaderNodeSeparateXYZ")
        L.new(geo.outputs["Position"], sep.inputs[0])
        mr = N.new("ShaderNodeMapRange")
        mr.inputs["From Min"].default_value = z0
        mr.inputs["From Max"].default_value = z1
        mr.inputs["To Min"].default_value = a0
        mr.inputs["To Max"].default_value = a1
        L.new(sep.outputs[axis], mr.inputs["Value"])
        L.new(mr.outputs["Result"], tone.inputs[1])
    else:
        tone.inputs[1].default_value = albedo
    # white where the wave is below the tone: the white share of each line period ~ tone
    white = N.new("ShaderNodeMath")
    white.operation = "LESS_THAN"
    L.new(wave.outputs["Fac"], white.inputs[0])
    L.new(tone.outputs[0], white.inputs[1])

    ink = N.new("ShaderNodeEmission")
    ink.inputs["Color"].default_value = INK
    paper = N.new("ShaderNodeEmission")
    paper.inputs["Color"].default_value = PAPER
    mix = N.new("ShaderNodeMixShader")
    L.new(white.outputs[0], mix.inputs["Fac"])
    L.new(ink.outputs[0], mix.inputs[1])
    L.new(paper.outputs[0], mix.inputs[2])
    out = N.new("ShaderNodeOutputMaterial")
    L.new(mix.outputs[0], out.inputs["Surface"])
    return mat


def highlight(name, threshold):
    """Ink with a paper-white stripe where the surface faces the light (strands of hair)."""
    mat = bpy.data.materials.new(name)
    nt = _nodes(mat)
    N, L = nt.nodes, nt.links
    geo = N.new("ShaderNodeNewGeometry")
    dot = N.new("ShaderNodeVectorMath")
    dot.operation = "DOT_PRODUCT"
    dot.inputs[1].default_value = LIGHT
    L.new(geo.outputs["Normal"], dot.inputs[0])
    gt = N.new("ShaderNodeMath")
    gt.operation = "GREATER_THAN"
    gt.inputs[1].default_value = threshold
    L.new(dot.outputs["Value"], gt.inputs[0])
    ink = N.new("ShaderNodeEmission")
    ink.inputs["Color"].default_value = INK
    paper = N.new("ShaderNodeEmission")
    paper.inputs["Color"].default_value = PAPER
    mix = N.new("ShaderNodeMixShader")
    L.new(gt.outputs[0], mix.inputs["Fac"])
    L.new(ink.outputs[0], mix.inputs[1])
    L.new(paper.outputs[0], mix.inputs[2])
    out = N.new("ShaderNodeOutputMaterial")
    L.new(mix.outputs[0], out.inputs["Surface"])
    return mat


def flat(name, color):
    mat = bpy.data.materials.new(name)
    nt = _nodes(mat)
    em = nt.nodes.new("ShaderNodeEmission")
    em.inputs["Color"].default_value = color
    out = nt.nodes.new("ShaderNodeOutputMaterial")
    nt.links.new(em.outputs[0], out.inputs["Surface"])
    return mat


def outline_material():
    """Inverted hull: only the far side of the shell (seen past the object's edge) is drawn."""
    mat = bpy.data.materials.new("outline")
    nt = _nodes(mat)
    N, L = nt.nodes, nt.links
    geo = N.new("ShaderNodeNewGeometry")
    ink = N.new("ShaderNodeEmission")
    ink.inputs["Color"].default_value = INK
    clear = N.new("ShaderNodeBsdfTransparent")
    mix = N.new("ShaderNodeMixShader")
    L.new(geo.outputs["Backfacing"], mix.inputs["Fac"])
    L.new(ink.outputs[0], mix.inputs[1])
    L.new(clear.outputs[0], mix.inputs[2])
    out = N.new("ShaderNodeOutputMaterial")
    L.new(mix.outputs[0], out.inputs["Surface"])
    return mat


def glass_material():
    """A perfect mirror with a few engraved glints across it."""
    mat = bpy.data.materials.new("mirror-glass")
    nt = _nodes(mat)
    N, L = nt.nodes, nt.links
    gl = N.new("ShaderNodeBsdfGlossy")
    gl.inputs["Color"].default_value = (0.97, 0.97, 0.97, 1.0)
    gl.inputs["Roughness"].default_value = 0.0
    tc = N.new("ShaderNodeTexCoord")
    sep = N.new("ShaderNodeSeparateXYZ")
    L.new(tc.outputs["Object"], sep.inputs[0])
    # diagonal coordinate u = x + 0.55 z (object space of the glass plane: x across, z up)
    diag = N.new("ShaderNodeMath")
    diag.operation = "MULTIPLY_ADD"
    diag.inputs[1].default_value = 0.55
    L.new(sep.outputs["Z"], diag.inputs[0])
    L.new(sep.outputs["X"], diag.inputs[2])
    glints = []
    for c, w in ((1.08, 0.022), (1.17, 0.008), (1.22, 0.004), (0.32, 0.012)):
        d = N.new("ShaderNodeMath"); d.operation = "SUBTRACT"; d.inputs[1].default_value = c
        L.new(diag.outputs[0], d.inputs[0])
        a = N.new("ShaderNodeMath"); a.operation = "ABSOLUTE"; L.new(d.outputs[0], a.inputs[0])
        t = N.new("ShaderNodeMath"); t.operation = "LESS_THAN"; t.inputs[1].default_value = w
        L.new(a.outputs[0], t.inputs[0])
        glints.append(t)
    acc = glints[0]
    for g in glints[1:]:
        m = N.new("ShaderNodeMath"); m.operation = "MAXIMUM"
        L.new(acc.outputs[0], m.inputs[0]); L.new(g.outputs[0], m.inputs[1])
        acc = m
    paper = N.new("ShaderNodeEmission")
    paper.inputs["Color"].default_value = PAPER
    mix = N.new("ShaderNodeMixShader")
    L.new(acc.outputs[0], mix.inputs["Fac"])
    L.new(gl.outputs[0], mix.inputs[1])
    L.new(paper.outputs[0], mix.inputs[2])
    out = N.new("ShaderNodeOutputMaterial")
    L.new(mix.outputs[0], out.inputs["Surface"])
    return mat


# ----------------------------------------------------------------------------- helpers
def link(obj):
    bpy.context.scene.collection.objects.link(obj)
    return obj


def mesh_object(name, bm, mats, smooth=False):
    me = bpy.data.meshes.new(name)
    bm.to_mesh(me)
    bm.free()
    for m in mats:
        me.materials.append(m)
    if smooth:
        for p in me.polygons:
            p.use_smooth = True
    return link(bpy.data.objects.new(name, me))


def add_outline(obj, mat, thickness):
    """A copy of obj pushed out along its normals with faces reversed."""
    bm = bmesh.new()
    bm.from_mesh(obj.data)
    bm.transform(obj.matrix_world)
    bm.normal_update()
    for v in bm.verts:
        v.co += v.normal * thickness
    bmesh.ops.reverse_faces(bm, faces=bm.faces)
    for f in bm.faces:
        f.material_index = 0
    shell = mesh_object(obj.name + "-outline", bm, [mat])
    return shell


def box(bm, center, size, rot=None):
    m = Matrix.Translation(center)
    if rot is not None:
        m = m @ rot
    m = m @ Matrix.Diagonal((size[0], size[1], size[2], 1.0))
    bmesh.ops.create_cube(bm, size=1.0, matrix=m)


def cylinder(bm, a, b, r1, r2=None, segments=20):
    a, b = Vector(a), Vector(b)
    d = b - a
    q = d.to_track_quat("Z", "Y")
    m = Matrix.Translation((a + b) / 2) @ q.to_matrix().to_4x4()
    bmesh.ops.create_cone(bm, cap_ends=True, segments=segments, radius1=r1,
                          radius2=r1 if r2 is None else r2, depth=d.length, matrix=m)


def sphere(bm, c, r):
    bmesh.ops.create_uvsphere(bm, u_segments=20, v_segments=12, radius=r, matrix=Matrix.Translation(c))


# ----------------------------------------------------------------------------- horse
def build_horse(mat):
    mb = bpy.data.metaballs.new("horse")
    mb.resolution = 0.05
    mb.render_resolution = 0.018
    mb.threshold = 0.6
    obj = link(bpy.data.objects.new("horse-mb", mb))

    def ball(c, r, stiff=2.0):
        e = mb.elements.new(type="BALL")
        e.co = c; e.radius = r; e.stiffness = stiff

    def capsule(a, b, r, stiff=2.0):
        a, b = Vector(a), Vector(b)
        d = b - a
        e = mb.elements.new(type="CAPSULE")
        e.co = (a + b) / 2
        e.size_x = d.length / 2
        e.radius = r
        e.stiffness = stiff
        e.rotation = d.to_track_quat("X", "Z")

    def leg(points, radii, side):
        for (p, q), r in zip(zip(points, points[1:]), radii):
            capsule((p[0], side * p[1], p[2]), (q[0], side * q[1], q[2]), r)

    # barrel, rearing at ~55 degrees
    capsule((-0.80, 0, 1.12), (-0.02, 0, 2.15), 0.42)
    ball((-0.86, 0, 1.12), 0.48)                    # hindquarters
    ball((-1.00, 0, 1.24), 0.36)                    # croup / buttock
    ball((0.08, 0, 2.12), 0.44)                     # chest
    ball((0.22, 0, 1.98), 0.30)                     # point of shoulder
    capsule((-0.55, 0, 1.30), (-0.20, 0, 1.75), 0.36)  # belly
    # neck, arched, and head
    capsule((0.05, 0, 2.35), (0.36, 0, 2.95), 0.29)
    capsule((0.30, 0, 2.80), (0.44, 0, 3.05), 0.20)
    # head: a long wedge from a broad cheek to a rounded muzzle
    poll, muzzle = Vector((0.44, 0, 3.04)), Vector((0.93, 0, 2.58))
    for t, r, drop in ((0.0, 0.16, 0.0), (0.15, 0.17, 0.05), (0.32, 0.145, 0.03), (0.5, 0.12, 0.0),
                       (0.68, 0.105, 0.0), (0.84, 0.105, 0.01), (1.0, 0.115, 0.03)):
        c = poll.lerp(muzzle, t) - Vector((0, 0, drop))
        ball(tuple(c), r * 1.7)
    ball((0.50, 0, 2.86), 0.30, stiff=1.8)            # cheek / jowl
    ball((0.47, 0, 3.05), 0.22, stiff=1.6)            # forehead
    for s in (-1, 1):
        capsule((0.42, 0.06 * s, 3.10), (0.36, 0.08 * s, 3.27), 0.045, stiff=1.6)  # ears
    # hind legs: stifle, hock bent back, hoof on the ground
    for s, dx in ((-1, 0.0), (1, 0.10)):
        leg([(-0.78 + dx, 0.20, 1.02), (-0.50 + dx, 0.22, 0.70), (-1.02 + dx, 0.19, 0.50),
             (-0.80 + dx, 0.18, 0.16), (-0.70 + dx, 0.18, 0.05)],
            [0.26, 0.15, 0.10, 0.09], s)
        ball((-0.68 + dx, 0.18 * s, 0.08), 0.11)  # hoof
        ball((-0.62 + dx, 0.21 * s, 0.88), 0.30)   # thigh / gaskin muscle
    # forelegs raised and folded, one higher than the other
    for s, (kx, kz, fx, fz) in ((-1, (0.56, 2.10, 0.48, 1.74)), (1, (0.52, 1.88, 0.56, 1.52))):
        leg([(0.18, 0.17, 1.92), (kx, 0.18, kz), (fx, 0.18, fz), (fx + 0.07, 0.18, fz - 0.10)],
            [0.17, 0.10, 0.09], s)
        ball((0.15, 0.16 * s, 1.88), 0.26)          # forearm muscle
        ball((fx + 0.08, 0.18 * s, fz - 0.12), 0.105)  # hoof

    dg = bpy.context.evaluated_depsgraph_get()
    me = bpy.data.meshes.new_from_object(obj.evaluated_get(dg))
    bpy.data.objects.remove(obj)
    me.name = "horse"
    me.materials.append(mat)
    for p in me.polygons:
        p.use_smooth = True
    return link(bpy.data.objects.new("horse", me))


def strand_curve(name, mat, splines):
    """splines: list of (points, radius_root, radius_tip)."""
    cu = bpy.data.curves.new(name, type="CURVE")
    cu.dimensions = "3D"
    cu.bevel_depth = 1.0
    cu.bevel_resolution = 2
    cu.use_fill_caps = True
    for pts, r0, r1 in splines:
        sp = cu.splines.new("NURBS")
        sp.points.add(len(pts) - 1)
        for i, p in enumerate(pts):
            t = i / (len(pts) - 1)
            sp.points[i].co = (p[0], p[1], p[2], 1.0)
            sp.points[i].radius = r0 + (r1 - r0) * t ** 0.8
        sp.order_u = 4
        sp.use_endpoint_u = True
    cu.materials.append(mat)
    obj = link(bpy.data.objects.new(name, cu))
    obj.matrix_world = HORSE_TURN
    return obj


def blown(root, direction, length, n, phase, amp, rng, lift=0.0, side=0.0):
    """Points of one strand streaming from root along direction, waving in the wind."""
    d = Vector(direction).normalized()
    perp = d.cross(Vector((0, 0, 1)))
    if perp.length < 1e-3:
        perp = Vector((0, 1, 0))
    perp.normalize()
    up = perp.cross(d).normalized()
    pts = []
    for i in range(n):
        t = i / (n - 1)
        wave = math.sin(t * 2.2 * math.pi + phase) * amp * t ** 1.2
        flutter = math.sin(t * 6.0 * math.pi + phase * 2.0 + rng.random()) * amp * 0.25 * t
        p = (Vector(root) + d * (length * t) + up * (wave + lift * t * t)
             + perp * (side * t + flutter))
        pts.append(p)
    return pts


def locks(rng, roots, count, per_lock, direction, length, amp, phase0, r0, lift, side, spread):
    """Strands grouped in locks: a lock shares its path, its strands fan out a little."""
    out = []
    for k in range(count):
        root = roots(k / max(count - 1, 1), rng)
        d = Vector(direction(k / max(count - 1, 1), rng))
        L = length(rng)
        ph = phase0 + k * 0.55 + rng.uniform(-0.3, 0.3)
        a = amp(rng)
        li, si = lift(rng), side(rng)
        for j in range(per_lock):
            off = Vector((rng.uniform(-1, 1) * spread, rng.uniform(-1, 1) * spread, rng.uniform(-1, 1) * spread))
            pts = blown(Vector(root) + off * 0.4, d + off * 0.6, L * rng.uniform(0.75, 1.05), 16,
                        ph + rng.uniform(-0.25, 0.25), a * rng.uniform(0.85, 1.15), rng,
                        lift=li + rng.uniform(-0.05, 0.05), side=si + rng.uniform(-0.06, 0.06))
            out.append((pts, r0 * rng.uniform(0.6, 1.0), 0.004))
    return out


def build_hair(mat, frame, frames):
    rng = random.Random(7)
    phase0 = -2 * math.pi * frame / max(frames, 1)
    poll, withers = Vector((0.36, 0.0, 3.10)), Vector((-0.06, 0.0, 2.46))
    mane = locks(
        rng,
        roots=lambda t, r: poll.lerp(withers, t) + Vector((r.uniform(-0.02, 0.02), r.uniform(-0.06, 0.06), 0.0)),
        count=16, per_lock=5,
        direction=lambda t, r: (-1.0, r.uniform(-0.15, 0.10), 0.22 + 0.30 * t),
        length=lambda r: r.uniform(1.0, 1.45),
        amp=lambda r: r.uniform(0.13, 0.22),
        phase0=phase0, r0=0.05,
        lift=lambda r: r.uniform(0.0, 0.3), side=lambda r: r.uniform(-0.2, 0.1), spread=0.06)
    mane += locks(
        rng,
        roots=lambda t, r: Vector((0.44, r.uniform(-0.04, 0.04), 3.11)),
        count=3, per_lock=4,
        direction=lambda t, r: (-0.7, r.uniform(-0.2, 0.1), 0.55),
        length=lambda r: r.uniform(0.4, 0.55),
        amp=lambda r: 0.06, phase0=phase0 + 1.0, r0=0.035,
        lift=lambda r: 0.05, side=lambda r: 0.0, spread=0.03)
    strand_curve("mane", mat, mane)
    tail_root = Vector((-1.16, 0.0, 1.32))
    tail = locks(
        rng,
        roots=lambda t, r: tail_root + Vector((0, r.uniform(-0.05, 0.05), r.uniform(-0.05, 0.05))),
        count=8, per_lock=5,
        direction=lambda t, r: (-1.0, r.uniform(-0.25, 0.15), -0.55 + 0.45 * t),
        length=lambda r: r.uniform(1.2, 1.65),
        amp=lambda r: r.uniform(0.15, 0.24),
        phase0=phase0 + 0.8, r0=0.065,
        lift=lambda r: r.uniform(0.15, 0.4), side=lambda r: r.uniform(-0.2, 0.15), spread=0.07)
    strand_curve("tail", mat, tail)


# ----------------------------------------------------------------------------- mirror
def build_mirror(wood, glass, outline, center, facing):
    """Cheval mirror: a tall framed glass tilting between two posts on splayed feet.

    Built facing -Y, then turned so its glass faces `facing` (a horizontal vector)."""
    W, H, zc, tilt = 0.78, 1.90, 1.36, math.radians(12)
    frame_w, frame_d = 0.07, 0.05
    tilt_m = Matrix.Rotation(-tilt, 4, "X")
    pivot = Vector((0, 0, zc))
    def tilted(v):
        return pivot + (tilt_m @ (Vector(v) - pivot))

    bm = bmesh.new()
    # frame around the glass, tilted back a little
    for (cx, cz, sx, sz) in ((0, H / 2 + frame_w / 2, W + 2 * frame_w, frame_w),
                             (0, -H / 2 - frame_w / 2, W + 2 * frame_w, frame_w),
                             (-W / 2 - frame_w / 2, 0, frame_w, H),
                             (W / 2 + frame_w / 2, 0, frame_w, H)):
        box(bm, tilted((cx, 0, zc + cz)), (sx, frame_d, sz), tilt_m)
    # crest rail on top of the frame
    box(bm, tilted((0, 0.0, zc + H / 2 + frame_w + 0.03)), (W * 0.6, frame_d * 0.8, 0.06), tilt_m)
    # posts, finials, feet, stretcher, pivot knobs
    px = W / 2 + frame_w + 0.07
    for s in (-1, 1):
        top = zc + H / 2 + 0.22
        cylinder(bm, (s * px, 0, 0.06), (s * px, 0, top), 0.036, 0.029)
        sphere(bm, (s * px, 0, top + 0.05), 0.06)
        box(bm, (s * px, 0, 0.04), (0.09, 0.70, 0.08))
        sphere(bm, (s * px, 0, zc), 0.045)
        cylinder(bm, (s * px, 0, zc), (s * (W / 2 + frame_w), 0, zc), 0.02)
    cylinder(bm, (-px, 0, 0.30), (px, 0, 0.30), 0.022)
    frame = mesh_object("mirror-frame", bm, [wood], smooth=False)

    bm = bmesh.new()
    bmesh.ops.create_grid(bm, x_segments=1, y_segments=1, size=0.5,
                          matrix=Matrix.Translation((0, 0, zc)) @ tilt_m @ Matrix.Rotation(math.pi / 2, 4, "X")
                          @ Matrix.Diagonal((W, H, 1, 1)))
    glass_obj = mesh_object("mirror-glass", bm, [glass])
    # turn the whole stand: local -Y must point along `facing`
    ang = math.atan2(facing.x, -facing.y)
    place = Matrix.Translation(center) @ Matrix.Rotation(ang, 4, "Z")
    for o in (frame, glass_obj):
        o.matrix_world = place
    # the glass's object space must stay "x across, z up" for its glints: keep it unscaled
    add_outline(frame, outline, 0.012)
    return glass_obj


# ----------------------------------------------------------------------------- scene
def build_scene(opts):
    bpy.ops.wm.read_factory_settings(use_empty=True)
    sc = bpy.context.scene
    sc.render.engine = "CYCLES"
    sc.cycles.samples = opts["samples"]
    # settings that moved or were renamed between Blender versions are best effort
    for owner, name, value in ((sc.cycles, "use_denoising", False), (sc.cycles, "max_bounces", 8),
                               (sc.cycles, "glossy_bounces", 3), (sc.cycles, "diffuse_bounces", 0),
                               (sc.cycles, "transmission_bounces", 0),
                               (sc.cycles, "transparent_max_bounces", 16),
                               (sc.cycles, "pixel_filter_width", 1.2), (sc.render, "filter_size", 1.2)):
        try:
            setattr(owner, name, value)
        except (AttributeError, TypeError):
            pass
    sc.render.resolution_x, sc.render.resolution_y = opts["res"]
    sc.render.resolution_percentage = 100
    sc.render.film_transparent = False
    sc.view_settings.view_transform = "Standard"
    sc.view_settings.look = "None"
    sc.render.image_settings.file_format = "PNG"
    sc.render.image_settings.color_mode = "RGB"
    try:
        sc.render.threads_mode = "AUTO"
    except Exception:
        pass

    world = bpy.data.worlds.new("paper")
    if bpy.app.version < (5, 0, 0):
        world.use_nodes = True
    bg = world.node_tree.nodes.get("Background")
    bg.inputs["Color"].default_value = PAPER
    bg.inputs["Strength"].default_value = 1.0
    sc.world = world

    horse_mat = engraving("horse", albedo=0.16, ambient=0.0, scale=8.5, distortion=1.4,
                          rotation=(0.0, math.radians(35), 0.0), detail=2.0)
    hair_mat = highlight("hair", 0.9)
    wood_mat = engraving("wood", albedo=0.55, ambient=0.15, scale=14.0, distortion=0.5,
                         direction="X")
    ground_mat = engraving("ground", albedo=0.80, ambient=0.80, scale=0.8, distortion=4.0,
                           direction="Y", coords="Object", detail=2.5)
    shadow_mat = engraving("shadow", albedo=0.40, ambient=1.0, scale=2.6, distortion=0.8,
                           direction="Y")
    sky_mat = engraving("sky", albedo=1.0, ambient=1.0, scale=2.2, distortion=0.25, direction="Z",
                        gradient=("Z", 0.5, 9.0, 1.02, 0.82))
    outline = outline_material()
    eye_mat = flat("eye", PAPER)

    horse = build_horse(horse_mat)
    horse.matrix_world = HORSE_TURN
    add_outline(horse, outline, 0.02)
    bm = bmesh.new()
    sphere(bm, (0.66, -0.135, 2.87), 0.026)
    mesh_object("eye", bm, [eye_mat]).matrix_world = HORSE_TURN

    cam_pos = Vector((0.55, -9.6, 1.05))
    horse_c = HORSE_TURN @ Vector((0.2, 0.0, 2.2))
    mirror_c = Vector((2.3, 0.95, 0.0))
    m_eye = mirror_c + Vector((0, 0, 1.4))
    facing = ((horse_c - m_eye).normalized() + (cam_pos - m_eye).normalized())
    facing.z = 0
    facing.normalize()
    build_mirror(wood_mat, glass_mat := glass_material(), outline, mirror_c, facing)

    # ground, the horse's shadow, the sky behind
    bm = bmesh.new()
    bmesh.ops.create_grid(bm, x_segments=1, y_segments=1, size=30.0)
    mesh_object("ground", bm, [ground_mat])
    bm = bmesh.new()
    bmesh.ops.create_circle(bm, cap_ends=True, segments=48, radius=1.0,
                            matrix=HORSE_TURN @ Matrix.Translation((-0.25, 0.55, 0.004)) @ Matrix.Diagonal((1.25, 0.55, 1, 1)))
    mesh_object("shadow", bm, [shadow_mat])
    bm = bmesh.new()
    bmesh.ops.create_circle(bm, cap_ends=True, segments=48, radius=1.0,
                            matrix=Matrix.Translation((2.5, 1.4, 0.004)) @ Matrix.Diagonal((0.75, 0.45, 1, 1)))
    mesh_object("mirror-shadow", bm, [shadow_mat])
    bm = bmesh.new()
    bmesh.ops.create_grid(bm, x_segments=1, y_segments=1, size=1.0,
                          matrix=Matrix.Translation((0, 14, 4)) @ Matrix.Rotation(math.pi / 2, 4, "X")
                          @ Matrix.Diagonal((60, 12, 1, 1)))
    mesh_object("sky", bm, [sky_mat])

    cam_data = bpy.data.cameras.new("camera")
    cam_data.lens = 44
    cam_data.sensor_width = 36
    cam = link(bpy.data.objects.new("camera", cam_data))
    cam.location = cam_pos
    target = Vector((0.85, 0.6, 1.62))
    cam.rotation_euler = (target - cam_pos).to_track_quat("-Z", "Y").to_euler()
    sc.camera = cam
    build_border(cam, opts["res"])
    return hair_mat


def build_border(cam, res):
    """A printed margin and a ruled ink border, fixed in front of the camera."""
    d = 0.5
    hw = d * cam.data.sensor_width / 2 / cam.data.lens
    hh = hw * res[1] / res[0]
    def ring(o, i):
        bm = bmesh.new()
        outer = [bm.verts.new((sx * o[0], sy * o[1], -d)) for sx, sy in ((-1, -1), (1, -1), (1, 1), (-1, 1))]
        inner = [bm.verts.new((sx * i[0], sy * i[1], -d)) for sx, sy in ((-1, -1), (1, -1), (1, 1), (-1, 1))]
        for k in range(4):
            bm.faces.new((outer[k], outer[(k + 1) % 4], inner[(k + 1) % 4], inner[k]))
        return bm
    m = 0.030 * hw          # paper margin
    line = 0.009 * hw       # ink rule
    for name, o, i, mat in (("border-paper", (hw * 1.01, hh * 1.01), (hw - m, hh - m), flat("border-paper", PAPER)),
                            ("border-ink", (hw - m, hh - m), (hw - m - line, hh - m - line), flat("border-ink", INK))):
        obj = mesh_object(name, ring(o, i), [mat])
        obj.parent = cam
        obj.matrix_parent_inverse = Matrix.Identity(4)
        try:
            obj.visible_glossy = False
            obj.visible_shadow = False
        except Exception:
            pass


def clear_hair():
    for name in ("mane", "tail"):
        o = bpy.data.objects.get(name)
        if o:
            cu = o.data
            bpy.data.objects.remove(o)
            bpy.data.curves.remove(cu)


def render(opts):
    os.makedirs(opts["out"], exist_ok=True)
    hair_mat = build_scene(opts)
    sc = bpy.context.scene
    frames = max(1, opts["frames"])
    for f in range(frames):
        clear_hair()
        build_hair(hair_mat, f, frames)
        name = "cheval.png" if frames == 1 else f"frame_{f:04d}.png"
        sc.render.filepath = os.path.join(opts["out"], name)
        bpy.ops.render.render(write_still=True)
        print(f"cheval-woodcut: wrote {sc.render.filepath}", flush=True)
    blend = os.path.join(opts["out"], "cheval_woodcut.blend")
    bpy.ops.wm.save_as_mainfile(filepath=blend, check_existing=False)
    print(f"cheval-woodcut: done ({frames} frame(s)); scene saved as {blend}", flush=True)


if __name__ == "__main__":
    if bpy.app.background:
        for job in parse_args():
            render(job)
    else:
        # Started from the UI: render in a separate background Blender so the UI stays responsive.
        import subprocess
        here = os.path.abspath(__file__) if "__file__" in globals() else CHEVAL_SCRIPT  # noqa: F821
        out = os.path.join(os.path.dirname(here), "render")
        os.makedirs(out, exist_ok=True)
        log = open(os.path.join(out, "render.log"), "w")
        subprocess.Popen([bpy.app.binary_path, "-b", "--factory-startup", "-P", here, "--", "--out", out]
                         + list(globals().get("CHEVAL_ARGS", [])), stdout=log, stderr=subprocess.STDOUT)
        print(f"rendering in the background; see {out}")
