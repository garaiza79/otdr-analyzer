"""Parser for EXFO .trc (native OTDR trace) files.

The .trc format is EXFO's proprietary binary format.  It stores multiple
wavelengths in a single file using an "AppReg" container with zlib-compressed
data blocks.  This module extracts metadata, events and trace data for each
wavelength so that the rest of the application can treat them identically to
parsed .sor files.
"""

import struct
import zlib
import math


# ── helpers ─────────────────────────────────────────────────────────

def _decompress_stream(raw: bytes) -> bytes:
    """Concatenate all full-size zlib blocks into a single byte stream."""
    blocks = []
    pos = 0
    while True:
        idx = raw.find(b"\x78\xda", pos)
        if idx == -1:
            break
        try:
            dec = zlib.decompress(raw[idx:])
            if len(dec) == 32768:
                blocks.append(dec)
        except zlib.error:
            pass
        pos = idx + 1
    return b"".join(blocks)


def _find_double(stream: bytes, name: bytes, start: int = 0) -> float | None:
    """Find a named field and return its IEEE-754 double value."""
    idx = stream.find(name + b"\x00", start)
    if idx == -1:
        return None
    after = idx + len(name) + 1
    if after + 8 > len(stream):
        return None
    return struct.unpack_from("<d", stream, after)[0]


def _find_all_doubles(stream: bytes, name: bytes) -> list[tuple[int, float]]:
    """Return all (offset, value) pairs for a named double field."""
    results = []
    pos = 0
    while True:
        idx = stream.find(name + b"\x00", pos)
        if idx == -1:
            break
        after = idx + len(name) + 1
        if after + 8 <= len(stream):
            results.append((idx, struct.unpack_from("<d", stream, after)[0]))
        pos = idx + 1
    return results


def _read_utf16le(stream: bytes, start: int, max_len: int = 200) -> str:
    """Read a null-terminated UTF-16LE string."""
    end = start
    while end < start + max_len and end + 1 < len(stream):
        if stream[end : end + 2] == b"\x00\x00":
            break
        end += 2
    return stream[start:end].decode("utf-16-le", errors="replace")


def _find_string(stream: bytes, name: bytes) -> str:
    """Find a named field and return its UTF-16LE string value."""
    idx = stream.find(name + b"\x00")
    if idx == -1:
        return "N/A"
    after = idx + len(name) + 1
    return _read_utf16le(stream, after) or "N/A"


# ── trace (raw samples) ────────────────────────────────────────────

def _extract_raw_samples(stream: bytes, trace_idx: int = 0):
    """Extract uint16 raw samples for a given trace.

    Returns (samples_list, sampling_period_s).
    """
    # Find the Nth RawSamples block
    pos = 0
    for _ in range(trace_idx + 1):
        idx = stream.find(b"RawSamples\x00", pos)
        if idx == -1:
            return [], 0
        if _ < trace_idx:
            pos = idx + 1

    after = idx + len(b"RawSamples\x00")

    # Size is stored 8 bytes before the name as uint32
    size_bytes = struct.unpack_from("<I", stream, idx - 8)[0]
    num_samples = size_bytes // 2

    samples = []
    for j in range(after, min(after + size_bytes, len(stream) - 1), 2):
        samples.append(struct.unpack_from("<H", stream, j)[0])

    # Find the corresponding SamplingPeriod
    sp_vals = _find_all_doubles(stream, b"SamplingPeriod")
    sp = sp_vals[trace_idx][1] if trace_idx < len(sp_vals) else 1.25e-8

    return samples, sp


# ── events ──────────────────────────────────────────────────────────

def _find_event_data_range(stream: bytes, trace_idx: int):
    """Find the byte range in *stream* that contains the event data for
    a given trace.  Returns (start, end) offsets or (0, 0) on failure.

    The EventTable for each trace contains EventN index entries whose
    first uint32 offset points into the event-data region.  We use the
    first event's first offset as *start* and the next trace's first
    offset (or a generous padding) as *end*.
    """
    import re as _re

    # Locate the Count field for this trace's event list.
    # Count fields that are ≥ 5 are likely event counts (not fiber/trace counts).
    count_offsets = []
    p = 0
    while True:
        idx = stream.find(b"Count\x00", p)
        if idx == -1:
            break
        val = struct.unpack_from("<I", stream, idx + 6)[0]
        if 5 <= val <= 200:  # plausible event count
            count_offsets.append((idx, val))
        p = idx + 1

    if trace_idx >= len(count_offsets):
        return 0, 0

    count_off, count_val = count_offsets[trace_idx]

    # Find Event0 entry near this Count (within ~1000 bytes)
    ev0_pos = stream.find(b"Event0\x00", count_off, count_off + 1000)
    if ev0_pos == -1:
        return 0, 0

    # First data offset from Event0 entry
    ev0_name_end = stream.find(b"\x00", ev0_pos)
    start = struct.unpack_from("<I", stream, ev0_name_end + 1)[0]

    # End: use next trace's event data start, or start + generous range
    if trace_idx + 1 < len(count_offsets):
        next_count_off = count_offsets[trace_idx + 1][0]
        next_ev0 = stream.find(b"Event0\x00", next_count_off, next_count_off + 1000)
        if next_ev0 != -1:
            ne = stream.find(b"\x00", next_ev0)
            end = struct.unpack_from("<I", stream, ne + 1)[0]
        else:
            end = start + 50000
    else:
        end = start + 50000

    return start, end


def _extract_events(stream: bytes, trace_idx: int = 0):
    """Extract events for a given trace (0-based).

    Each event has Position, Loss, Reflectance and Type.
    """
    start, end = _find_event_data_range(stream, trace_idx)
    if start == 0 and end == 0:
        return []

    end = min(end, len(stream))
    events = []
    seen_positions = set()
    p = start

    while p < end:
        pidx = stream.find(b"Position\x00", p)
        if pidx == -1 or pidx >= end:
            break

        after_pos = pidx + 9  # len("Position\0")
        if after_pos + 8 > len(stream):
            break

        # Verify Length follows shortly after (distinguishes event Position
        # from cursor Position fields)
        check = stream[after_pos + 8 : after_pos + 60]
        if b"Length\x00" not in check:
            p = pidx + 1
            continue

        pos_val = struct.unpack_from("<d", stream, after_pos)[0]
        pos_km = round(pos_val / 1000, 4)

        # Skip duplicates
        pos_key = round(pos_val, 1)
        if pos_key in seen_positions:
            p = pidx + 1
            continue
        seen_positions.add(pos_key)

        # Extract Type, Loss, Reflectance from surrounding ~500 bytes
        block = stream[pidx : pidx + 500]

        type_idx = block.find(b"Type\x00")
        type_val = None
        if type_idx > 0 and type_idx + 9 <= len(block):
            type_val = struct.unpack_from("<I", block, type_idx + 5)[0]

        loss_idx = block.find(b"Loss\x00")
        loss_val = 0.0
        if loss_idx > 0 and loss_idx + 13 <= len(block):
            loss_val = struct.unpack_from("<d", block, loss_idx + 5)[0]
            if math.isnan(loss_val):
                loss_val = 0.0

        ref_idx = block.find(b"Reflectance\x00")
        ref_val = 0.0
        if ref_idx > 0 and ref_idx + 20 <= len(block):
            ref_val = struct.unpack_from("<d", block, ref_idx + 12)[0]
            if math.isnan(ref_val):
                ref_val = 0.0

        events.append({
            "position_m": pos_val,
            "position_km": pos_km,
            "type_code": type_val,
            "loss_db": round(loss_val, 4),
            "reflectance_db": round(ref_val, 2),
        })

        p = pidx + 1

    # Sort by position and remove negative-position events (pre-connector)
    events = [e for e in events if e["position_m"] >= -0.1]
    events.sort(key=lambda e: e["position_m"])

    return events


# ── main public API ─────────────────────────────────────────────────

def _classify_trc_event(type_code, idx, total):
    """Classify an event from its numeric type code."""
    if idx == total - 1:
        return "Fin de fibra"
    if type_code == 3:
        if idx == 0:
            return "Conector (inicio)"
        return "Conector / Reflexion"
    elif type_code == 2:
        return "Empalme (fusion)"
    elif type_code == 1:
        return "Empalme (mecanico)"
    else:
        return "Evento"


def parse_trc_file(filepath: str) -> list[dict]:
    """Parse an EXFO .trc file and return a list of analysis results.

    Each element corresponds to one wavelength (trace) in the file and
    has the same structure as the dict returned by ``parse_sor_file``.
    """
    with open(filepath, "rb") as f:
        raw = f.read()

    # Verify magic
    if not raw.startswith(b"AppReg Format Ex"):
        raise ValueError("No es un archivo .trc valido (encabezado incorrecto).")

    stream = _decompress_stream(raw)
    if not stream:
        raise ValueError("No se pudieron descomprimir los datos del archivo .trc.")

    # ── metadata (shared across wavelengths) ───────────────────────
    location_a = _find_string(stream, b"LocationA")
    location_b = _find_string(stream, b"LocationB")
    cable = _find_string(stream, b"Cable")
    fiber_code = _find_string(stream, b"FiberCode")
    identifier = _find_string(stream, b"Identifier")

    # ── per-trace data ─────────────────────────────────────────────
    # Discover how many traces exist (Trace0, Trace1, …)
    trace_count_field = _find_all_doubles(stream, b"SamplingPeriod")
    num_traces = len(trace_count_field) if trace_count_field else 1

    # Wavelengths – NominalWavelength appears once per acquisition set
    wl_all = _find_all_doubles(stream, b"NominalWavelength")
    # Deduplicate keeping order (each wavelength appears 3× for stitched acquisitions)
    unique_wls = []
    seen_wl = set()
    for _, wl in wl_all:
        nm = round(wl * 1e9)
        if nm not in seen_wl:
            seen_wl.add(nm)
            unique_wls.append(nm)

    # Pulse widths
    pw_all = _find_all_doubles(stream, b"NominalPulseWidth")
    unique_pws = []
    seen_pw = set()
    for _, pw in pw_all:
        ns = round(pw * 1e9)
        if ns not in seen_pw:
            seen_pw.add(ns)
            unique_pws.append(ns)

    # IOR: derive from DisplayRange / (num_samples * dist_per_sample)
    # or use standard EXFO default 1.46820
    ior = 1.46820

    # ORL and total span loss (one per trace)
    orl_vals = _find_all_doubles(stream, b"TotalOrl")
    spans_loss_vals = _find_all_doubles(stream, b"SpansLoss")

    results = []

    for t_idx in range(num_traces):
        wl_nm = unique_wls[t_idx] if t_idx < len(unique_wls) else 0
        pw_ns = unique_pws[0] if unique_pws else 0

        # Raw samples & sampling period
        samples, sampling_period = _extract_raw_samples(stream, t_idx)
        if not samples:
            continue

        # Distance per sample
        c = 299792458.0
        dist_per_sample = (sampling_period * c) / (2 * ior)

        # Build trace arrays (downsampled for browser)
        max_points = 2000
        step = max(1, len(samples) // max_points)
        distances_km = []
        power_db = []
        for i in range(0, len(samples), step):
            d = round(i * dist_per_sample / 1000, 4)
            p = round(samples[i] / 1000.0, 3)  # raw → dB (milli-dB units)
            distances_km.append(d)
            power_db.append(p)

        total_distance_km = round(len(samples) * dist_per_sample / 1000, 4)

        # Events
        raw_events = _extract_events(stream, t_idx)
        events = []
        for i, evt in enumerate(raw_events):
            events.append({
                "number": i + 1,
                "distance_km": evt["position_km"],
                "splice_loss_db": evt["loss_db"],
                "reflection_db": evt["reflectance_db"],
                "slope_db_km": 0.0,
                "event_type_code": str(evt["type_code"] or ""),
                "event_type": _classify_trc_event(evt["type_code"], i, len(raw_events)),
                "comments": "",
            })

        # Total loss from SpansLoss field, fallback to sum of positive splice losses
        if t_idx < len(spans_loss_vals):
            total_loss = round(spans_loss_vals[t_idx][1], 4)
        else:
            total_loss = round(sum(e["splice_loss_db"] for e in events if e["splice_loss_db"] > 0), 4)

        # ORL from TotalOrl field
        orl = 0.0
        if t_idx < len(orl_vals):
            orl = round(orl_vals[t_idx][1], 2)

        fiber_length = events[-1]["distance_km"] if events else total_distance_km

        result = {
            "metadata": {
                "cable_id": cable,
                "fiber_id": identifier,
                "wavelength_nm": f"{wl_nm} nm",
                "location_a": location_a,
                "location_b": location_b,
                "fiber_type": fiber_code,
                "build_condition": "N/A",
                "operator": "N/A",
                "otdr_manufacturer": "EXFO",
                "otdr_model": "N/A",
                "otdr_serial": "N/A",
                "module": "N/A",
                "module_serial": "N/A",
                "software_version": "N/A",
                "pulse_width_ns": pw_ns,
                "range_km": total_distance_km,
                "index_of_refraction": ior,
                "date_time": "N/A",
                "calibration_date": "N/A",
            },
            "events": events,
            "summary": {
                "total_loss_db": total_loss,
                "fiber_length_km": round(fiber_length, 4),
                "orl_db": orl,
                "num_events": len(events),
            },
            "trace": {
                "distances_km": distances_km,
                "power_db": power_db,
            },
            "_wavelength_nm": wl_nm,
        }
        results.append(result)

    if not results:
        raise ValueError("No se encontraron trazas en el archivo .trc.")

    return results
