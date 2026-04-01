"""OTDR .sor file analyzer - Flask backend."""
import os
import re
import struct
import tempfile
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory

from pyotdr import read as pyotdr_read
import pyotdr.parts as _pyotdr_parts

# Monkey-patch pyotdr to handle latin-1 encoded strings in .sor files.
# Some OTDR vendors (e.g., EXFO) store location names with accented
# characters (latin-1), but pyotdr hardcodes utf-8 decoding.
_original_get_string = _pyotdr_parts.get_string


def _get_string_latin1(fh):
    import struct
    mystr = b""
    byte = fh.read(1)
    while byte != "" and byte != b"":
        tt = struct.unpack("c", byte)[0]
        if tt == b"\x00":
            break
        mystr += tt
        byte = fh.read(1)
    return mystr.decode("latin-1")


_pyotdr_parts.get_string = _get_string_latin1

app = Flask(__name__, static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB max


def parse_sor_file(filepath):
    """Parse a .sor file using pyOTDR and return structured data."""
    # pyotdr.read.sorparse returns (status, results_dict, tracedata_list)
    status, results, tracedata = pyotdr_read.sorparse(filepath)

    if status != "ok":
        raise ValueError(f"Error parsing SOR file: {status}")

    gen_params = results.get("GenParams", {})
    fxd_params = results.get("FxdParams", {})
    sup_params = results.get("SupParams", {})
    key_events = results.get("KeyEvents", {})

    # Build metadata
    # wavelength can be a string like "1310 nm" or a number
    wavelength_raw = gen_params.get("wavelength", fxd_params.get("wavelength", "N/A"))
    if isinstance(wavelength_raw, str):
        wavelength_nm = wavelength_raw.strip()
    elif isinstance(wavelength_raw, (int, float)):
        wavelength_nm = f"{wavelength_raw / 10 if wavelength_raw > 2000 else wavelength_raw} nm"
    else:
        wavelength_nm = str(wavelength_raw)

    range_val = fxd_params.get("range", 0)
    if isinstance(range_val, (int, float)):
        range_km = round(range_val, 2)
    else:
        range_km = 0

    # Extract calibration date from ExfoAdditionalInfo block
    calibration_date = extract_calibration_date(filepath)

    metadata = {
        "cable_id": gen_params.get("cable ID", "N/A"),
        "fiber_id": gen_params.get("fiber ID", "N/A"),
        "wavelength_nm": wavelength_nm,
        "location_a": gen_params.get("location A", gen_params.get("locationA", "N/A")),
        "location_b": gen_params.get("location B", gen_params.get("locationB", "N/A")),
        "fiber_type": gen_params.get("cable code/fiber type", gen_params.get("fiber type", "N/A")),
        "build_condition": gen_params.get("build condition", "N/A"),
        "operator": gen_params.get("operator", "N/A"),
        "otdr_manufacturer": sup_params.get("supplier", "N/A"),
        "otdr_model": sup_params.get("OTDR", "N/A"),
        "otdr_serial": sup_params.get("OTDR S/N", "N/A"),
        "module": sup_params.get("module", "N/A"),
        "module_serial": sup_params.get("module S/N", "N/A"),
        "software_version": sup_params.get("software", "N/A"),
        "pulse_width_ns": fxd_params.get("pulse width", "N/A"),
        "range_km": range_km,
        "index_of_refraction": fxd_params.get("index", "N/A"),
        "date_time": fxd_params.get("date/time", "N/A"),
        "calibration_date": calibration_date,
    }

    # Extract events - pyotdr uses "event 1", "event 2", etc. keys
    # Values are stored as strings, need to convert to float
    events = []
    num_events = key_events.get("num events", 0)

    for i in range(1, num_events + 1):
        evt = key_events.get("event %d" % i, {})
        if not evt:
            continue

        event_type_str = evt.get("type", "")
        event_type = classify_event(event_type_str, i, num_events)

        events.append({
            "number": i,
            "distance_km": float(evt.get("distance", "0")),
            "splice_loss_db": float(evt.get("splice loss", "0")),
            "reflection_db": float(evt.get("refl loss", "0")),
            "slope_db_km": float(evt.get("slope", "0")),
            "event_type_code": event_type_str,
            "event_type": event_type,
            "comments": evt.get("comments", ""),
        })

    # Summary from KeyEvents
    summary_data = key_events.get("Summary", {})
    fiber_length = summary_data.get("loss end", 0)
    if fiber_length == 0 and events:
        fiber_length = events[-1]["distance_km"]

    summary = {
        "total_loss_db": summary_data.get("total loss", 0),
        "fiber_length_km": round(fiber_length, 4),
        "orl_db": summary_data.get("ORL", 0),
        "num_events": num_events,
    }

    # Extract trace data from tracedata list
    # tracedata is a list of strings like "0.001234\t3.456000\n"
    trace = extract_trace(tracedata)

    return {
        "metadata": metadata,
        "events": events,
        "summary": summary,
        "trace": trace,
    }


def extract_calibration_date(filepath):
    """Extract calibration date from ExfoAdditionalInfo block in .sor file.

    EXFO OTDRs store a unix timestamp (midnight UTC) in the
    ExfoAdditionalInfo block that corresponds to the module
    calibration date.
    """
    try:
        with open(filepath, "rb") as f:
            raw = f.read()

        # Search for the ExfoAdditionalInfo block data (not the map entry)
        # The block name appears twice: once in the map block (early in file)
        # and once at the actual block position. We need the last occurrence.
        marker = b"ExfoAdditionalInfo\x00"
        pos = raw.rfind(marker)
        if pos == -1:
            return "N/A"

        # After the null-terminated name, the next 4 bytes are a uint32 LE timestamp
        data_start = pos + len(marker)
        if data_start + 4 > len(raw):
            return "N/A"

        ts = struct.unpack_from("<I", raw, data_start)[0]

        # Validate: should be a reasonable date (2010-2040)
        if ts < 1262304000 or ts > 2208988800:  # 2010 to 2040
            return "N/A"

        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return "N/A"


def classify_event(type_code, event_num, total_events):
    """Classify an event based on its type code and position."""
    if not type_code:
        if event_num == total_events:
            return "Fin de fibra"
        return "Desconocido"

    # Last event is typically end of fiber
    if event_num == total_events:
        return "Fin de fibra"

    first_char = type_code[0] if type_code else ""

    if first_char == "0":
        return "Empalme (fusion)"
    elif first_char == "1":
        if event_num == 1:
            return "Conector (inicio)"
        return "Conector / Reflexion"
    elif first_char == "2":
        return "Evento saturado / Reflexion fuerte"
    else:
        return "Evento"


def extract_trace(tracedata):
    """Extract trace data from pyotdr tracedata list for graphing."""
    trace = {"distances_km": [], "power_db": []}

    if not tracedata:
        return trace

    total_points = len(tracedata)

    # Downsample for browser performance
    max_points = 2000
    step = max(1, total_points // max_points)

    for i in range(0, total_points, step):
        line = tracedata[i].strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) == 2:
            try:
                dist = float(parts[0])
                power = float(parts[1])
                trace["distances_km"].append(round(dist, 4))
                trace["power_db"].append(round(power, 3))
            except ValueError:
                continue

    return trace


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No se proporciono archivo"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No se selecciono archivo"}), 400

    if not file.filename.lower().endswith(".sor"):
        return jsonify({"error": "El archivo debe ser .sor"}), 400

    # Save to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sor") as tmp:
        file.save(tmp.name)
        tmp_path = tmp.name

    try:
        result = parse_sor_file(tmp_path)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Error al analizar el archivo: {str(e)}"}), 500
    finally:
        os.unlink(tmp_path)


def extract_drive_file_id(url):
    """Extract Google Drive file ID from various URL formats."""
    patterns = [
        r'/file/d/([a-zA-Z0-9_-]+)',
        r'[?&]id=([a-zA-Z0-9_-]+)',
        r'/open\?id=([a-zA-Z0-9_-]+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None


def download_google_drive_file(file_id, dest_path):
    """Download a file from Google Drive using gdown."""
    import gdown

    url = f"https://drive.google.com/uc?id={file_id}"
    try:
        output = gdown.download(url, dest_path, quiet=True, fuzzy=True)
    except Exception:
        output = None

    if not output or not os.path.exists(dest_path):
        raise ValueError(
            "No se pudo descargar el archivo de Google Drive. "
            "Verifica que el archivo este compartido como "
            "'Cualquier persona con el enlace'."
        )

    # Verify we didn't get an HTML page
    file_size = os.path.getsize(dest_path)
    if file_size < 100:
        raise ValueError(
            f"El archivo descargado es muy pequeno ({file_size} bytes). "
            "Verifica el enlace."
        )

    with open(dest_path, "rb") as f:
        header = f.read(15)
    if header.startswith(b"<!doctype") or header.startswith(b"<html"):
        raise ValueError(
            "Google Drive devolvio una pagina HTML en vez del archivo. "
            "Verifica que el archivo este compartido como "
            "'Cualquier persona con el enlace'."
        )


@app.route("/api/analyze-drive", methods=["POST"])
def analyze_drive():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "No se proporciono URL"}), 400

    url = data["url"].strip()
    file_id = extract_drive_file_id(url)
    if not file_id:
        return jsonify({"error": "No se pudo extraer el ID del archivo de Google Drive"}), 400

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sor") as tmp:
            tmp_path = tmp.name
        download_google_drive_file(file_id, tmp_path)
    except Exception as e:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return jsonify({"error": f"Error descargando archivo de Drive: {str(e)}"}), 500

    try:
        result = parse_sor_file(tmp_path)
        result["_drive_url"] = url
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Error al analizar el archivo: {str(e)}"}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
