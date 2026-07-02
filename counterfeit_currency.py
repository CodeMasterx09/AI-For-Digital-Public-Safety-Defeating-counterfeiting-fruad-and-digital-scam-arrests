"""
Counterfeit Currency Identification Agent — heuristic computer-vision demo.

IMPORTANT: This is a heuristic stand-in for a hackathon demo, NOT a trained
forensic model. It approximates the *kind* of signals a real CV pipeline
would fuse using only Pillow (no torch/tensorflow needed).

v2 improvements:
  - Added overbrightness / flat-print detection (catches toy/educational notes
    printed on plain paper — e.g. "Children Bank of India" school specimens)
  - Added color-channel ratio check per denomination (e.g. genuine ₹20 is
    greenish-yellow: G > R; toy ₹20 images are often pale yellow: R ≈ G >> B)
  - Added guilloche-background uniformity check (genuine notes have complex
    repeating patterns; flat prints are too uniform across patches)
  - Added serial-region anomaly check: repeated identical serial zones AND
    abnormally low dark-pixel density in serial bands = specimen/zero serial
  - Added aspect-ratio sanity check (real INR notes are landscape, w/h ≈ 2.0-2.1)
  - Hardened hard-fail logic: any one of the strong forgery signals alone now
    triggers LIKELY_COUNTERFEIT regardless of how many soft checks pass
"""
import base64
import io
import statistics

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Dominant-color profiles per INR denomination (demo only)
DENOMINATION_PROFILES = {
    "10":   {"rgb": (140, 90, 60),   "name": "₹10 (Chocolate Brown)",  "channel_bias": "R"},
    "20":   {"rgb": (170, 180, 60),  "name": "₹20 (Greenish Yellow)",  "channel_bias": "G"},
    "50":   {"rgb": (90, 150, 200),  "name": "₹50 (Fluorescent Blue)", "channel_bias": "B"},
    "100":  {"rgb": (150, 120, 170), "name": "₹100 (Lavender)",        "channel_bias": "B"},
    "200":  {"rgb": (210, 180, 60),  "name": "₹200 (Bright Yellow)",   "channel_bias": "G"},
    "500":  {"rgb": (110, 110, 100), "name": "₹500 (Stone Grey)",      "channel_bias": "N"},
}

def _color_distance(c1, c2):
    return sum((a - b) ** 2 for a, b in zip(c1, c2)) ** 0.5

def _closest_denomination(avg_rgb):
    best, best_dist = None, float("inf")
    for denom, profile in DENOMINATION_PROFILES.items():
        d = _color_distance(avg_rgb, profile["rgb"])
        if d < best_dist:
            best, best_dist = denom, d
    return best, best_dist

def _channel_ratios(img):
    """Return mean R, G, B channels for the full image."""
    all_px = list(img.getdata())
    r = statistics.mean(p[0] for p in all_px)
    g = statistics.mean(p[1] for p in all_px)
    b = statistics.mean(p[2] for p in all_px)
    return r, g, b

def _channel_bias_check(matched_denom, r, g, b):
    """
    Genuine notes have a dominant channel matching their denomination color.
    e.g. ₹20 (greenish-yellow) needs G > R by at least a small margin.
    Toy/printed fakes often appear as pale, washed-out yellows where R ≈ G.
    Returns (pass: bool, detail: str)
    """
    bias = DENOMINATION_PROFILES.get(matched_denom, {}).get("channel_bias", "N")
    if bias == "G":
        ok = g > r - 5   # G should be dominant or very close
        return ok, f"G={round(g,1)} R={round(r,1)} B={round(b,1)} (₹{matched_denom} expects G≥R)"
    if bias == "B":
        ok = b > r - 10
        return ok, f"B={round(b,1)} R={round(r,1)} G={round(g,1)} (₹{matched_denom} expects B dominant)"
    if bias == "R":
        ok = r > g - 5
        return ok, f"R={round(r,1)} G={round(g,1)} B={round(b,1)} (₹{matched_denom} expects R dominant)"
    return True, f"R={round(r,1)} G={round(g,1)} B={round(b,1)} (no strong channel bias for ₹{matched_denom})"

def _overbrightness_check(img):
    """
    Genuine INR notes have complex security backgrounds (guilloche, latent images,
    colour-shift ink) that produce a mean brightness well below a plain flat print.
    Educational/toy notes printed on plain yellow paper are typically too bright.
    Threshold: mean brightness > 175 AND mid-band uniformity > 0.68 = suspicious.
    Returns (pass: bool, detail: str)
    """
    all_px = list(img.getdata())
    brightness = [(p[0]+p[1]+p[2])/3 for p in all_px]
    mean_b = statistics.mean(brightness)
    # What fraction of pixels fall in a narrow "flat colour" band?
    mid_band = sum(1 for b in brightness if 145 < b < 230) / len(brightness)
    flat_print = mean_b > 175 and mid_band > 0.68
    detail = (f"brightness={round(mean_b,1)}/255, mid-band uniformity={round(mid_band*100,1)}% "
              f"({'flat/plain-paper print' if flat_print else 'OK'})")
    return not flat_print, detail

def _guilloche_uniformity_check(img):
    """
    Genuine notes have guilloche (fine repeating rosette) backgrounds that cause
    HIGH spatial variance across image patches. Flat/toy prints are too uniform.
    We tile the image into a 10×10 grid of patches and measure stdev of patch means.
    Real notes: patch stdev > 28. Toy/specimen prints: patch stdev < 22.
    Returns (pass: bool, detail: str)
    """
    w, h = img.size
    grid = 10
    patch_means = []
    for row in range(grid):
        for col in range(grid):
            x0, x1 = int(col*w/grid), int((col+1)*w/grid)
            y0, y1 = int(row*h/grid), int((row+1)*h/grid)
            crop = img.crop((x0, y0, x1, y1))
            px = list(crop.getdata())
            if px:
                patch_means.append(statistics.mean((p[0]+p[1]+p[2])/3 for p in px))
    stdev = statistics.pstdev(patch_means) if len(patch_means) > 1 else 0
    ok = stdev >= 25
    return ok, f"patch-mean stdev={round(stdev,1)} (genuine notes > 25; flat prints < 22)"

def _aspect_ratio_check(img):
    """
    Real INR notes are landscape: width/height ≈ 1.9–2.2 depending on denomination.
    Portrait or near-square images are unlikely to be genuine notes.
    """
    w, h = img.size
    ratio = w / h
    ok = 1.7 <= ratio <= 2.4
    return ok, f"aspect ratio {round(ratio, 2)} ({'OK' if ok else 'suspicious — not landscape 1.7–2.4'})"

def _edge_density(gray_img):
    w, h = gray_img.size
    px = gray_img.load()
    step = max(1, w // 200)
    diffs = []
    for y in range(0, h, max(1, h // 100)):
        for x in range(0, w - step, step):
            diffs.append(abs(px[x, y] - px[x + step, y]))
    return statistics.mean(diffs) if diffs else 0

def _print_variance(gray_img):
    w, h = gray_img.size
    px = gray_img.load()
    y0, y1 = int(h * 0.45), int(h * 0.55)
    samples = [px[x, y] for y in range(y0, y1) for x in range(0, w, max(1, w // 150))]
    return statistics.pstdev(samples) if len(samples) > 1 else 0

def _region_stats(img, box):
    crop = img.crop(box)
    pixels = list(crop.getdata())
    if not pixels:
        return {"brightness": 0, "saturation": 0, "dark_ratio": 0, "light_ratio": 0}
    brightness = [(p[0]+p[1]+p[2]) / 3 for p in pixels]
    saturation = [max(p[:3]) - min(p[:3]) for p in pixels]
    return {
        "brightness": statistics.mean(brightness),
        "saturation": statistics.mean(saturation),
        "dark_ratio": sum(1 for b in brightness if b < 85) / len(brightness),
        "light_ratio": sum(1 for b in brightness if b > 220) / len(brightness),
    }

def _stock_or_margin_strip_score(img):
    w, h = img.size
    bands = {
        "top":    (0, 0, w, max(1, int(h * 0.08))),
        "bottom": (0, int(h * 0.88), w, h),
        "left":   (0, 0, max(1, int(w * 0.05)), h),
        "right":  (int(w * 0.95), 0, w, h),
    }
    strip_hits = []
    for name, box in bands.items():
        s = _region_stats(img, box)
        if s["brightness"] > 210 and s["saturation"] < 22 and s["light_ratio"] > 0.55:
            strip_hits.append(name)
    return strip_hits

def _security_thread_score(gray_img):
    w, h = gray_img.size
    px = gray_img.load()
    y_start, y_end = int(h * 0.16), int(h * 0.84)
    x_start, x_end = int(w * 0.35), int(w * 0.72)
    if x_end <= x_start or y_end <= y_start:
        return 0
    scores = []
    step_y = max(1, h // 120)
    for x in range(x_start + 1, x_end - 1):
        hits, samples = 0, 0
        for y in range(y_start, y_end, step_y):
            center = px[x, y]
            left_v = px[x - 1, y]
            right_v = px[x + 1, y]
            if center + 10 < ((left_v + right_v) / 2):
                hits += 1
            samples += 1
        if samples:
            scores.append(hits / samples)
    return max(scores) if scores else 0

def _serial_number_check(img):
    """
    Genuine INR notes have TWO unique serial numbers — they differ from each other
    and both contain non-zero alphanumeric characters.

    Red flags caught here:
    1. IDENTICAL serial zones: top-left vs bottom-right regions are too similar
       in brightness profile (toy notes like 'IBB 000000' repeat the same text).
    2. ZERO-SERIAL: serial regions have very low dark-pixel density — means
       the serial digits are nearly invisible / not genuinely printed (specimen notes,
       education notes with placeholder '000000').
    3. LOW COMPLEXITY in serial bands: real serials have diverse characters;
       a band of all-zeros has near-zero pixel variance.

    Returns (pass: bool, detail: str)
    """
    w, h = img.size
    gray = img.convert("L")

    tl = gray.crop((int(w*0.02), int(h*0.06), int(w*0.30), int(h*0.22)))
    br = gray.crop((int(w*0.68), int(h*0.75), int(w*0.98), int(h*0.94)))

    tl_small = tl.resize((24, 8))
    br_small = br.resize((24, 8))
    tl_pix = list(tl_small.getdata())
    br_pix = list(br_small.getdata())

    # 1. Similarity between the two serial zones
    pixel_diff = statistics.mean(abs(a - b) for a, b in zip(tl_pix, br_pix))

    # 2. Dark pixel density in each serial zone (real ink = dark pixels)
    def dark_ratio(region):
        px = list(region.getdata())
        return sum(1 for p in px if p < 115) / len(px) if px else 0

    tl_dark = dark_ratio(tl)
    br_dark = dark_ratio(br)
    combined_dark = (tl_dark + br_dark) / 2

    # 3. Pixel variance within serial zone (all-zeros = very low variance)
    tl_px_full = list(tl.getdata())
    tl_variance = statistics.pstdev(tl_px_full) if len(tl_px_full) > 1 else 0

    flags = []
    if pixel_diff < 30:
        flags.append(f"serial zones too similar (diff={round(pixel_diff,1)} < 30)")
    if combined_dark < 0.04:
        flags.append(f"serial ink too faint/absent (dark_ratio={round(combined_dark,3)})")
    if tl_variance < 18:
        flags.append(f"serial region low complexity (variance={round(tl_variance,1)})")

    ok = len(flags) == 0
    detail = "; ".join(flags) if flags else (
        f"serial zones differ (diff={round(pixel_diff,1)}), "
        f"ink present (dark={round(combined_dark,3)}), variance={round(tl_variance,1)}"
    )
    return ok, detail

def _suspicious_serial_layout(gray_img):
    rgb = gray_img.convert("RGB")
    w, h = gray_img.size
    top_left = _region_stats(rgb, (int(w*0.02), int(h*0.12), int(w*0.32), int(h*0.34)))
    bottom_right = _region_stats(rgb, (int(w*0.66), int(h*0.62), int(w*0.98), int(h*0.86)))
    return top_left["dark_ratio"] > 0.10 and bottom_right["dark_ratio"] > 0.10


def analyze_note(image_bytes: bytes, claimed_denomination: str = None):
    if not PIL_AVAILABLE:
        return {
            "verdict": "ANALYSIS_UNAVAILABLE",
            "confidence": 0,
            "message": "Pillow not installed — run `pip install pillow` to enable image analysis.",
        }

    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception as e:
        return {"verdict": "INVALID_IMAGE", "confidence": 0, "message": f"Could not read image: {e}"}

    # --- Run checks on ORIGINAL resolution first (for serial/brightness checks) ---
    orig_img = img.copy()

    # Thumbnail for heavier per-pixel checks
    img.thumbnail((600, 600))
    gray = img.convert("L")

    # 1. Dominant color
    avg_rgb = img.resize((1, 1)).getpixel((0, 0))
    matched_denom, color_dist = _closest_denomination(avg_rgb)
    color_check_pass = color_dist < 95

    # 2. Edge density
    edge_density = _edge_density(gray)
    edge_check_pass = edge_density > 5.5

    # 3. Print variance
    variance = _print_variance(gray)
    variance_check_pass = variance > 10

    # 4. Stock/margin strip
    strip_hits = _stock_or_margin_strip_score(img)
    clean_frame_pass = not strip_hits

    # 5. Security thread
    thread_score = _security_thread_score(gray)
    thread_check_pass = thread_score > 0.40

    # 6. Old serial layout
    serial_layout_suspicious = _suspicious_serial_layout(gray)
    serial_check_pass = not serial_layout_suspicious

    # 7. Denomination match
    denomination_check_pass = True
    if claimed_denomination:
        denomination_check_pass = str(claimed_denomination) == str(matched_denom)

    # ---- NEW v2 checks ----

    # 8. Overbrightness / flat-print detection
    bright_pass, bright_detail = _overbrightness_check(img)

    # 9. Guilloche background uniformity
    guilloche_pass, guilloche_detail = _guilloche_uniformity_check(img)

    # 10. Color channel ratio vs denomination
    r_avg, g_avg, b_avg = _channel_ratios(img)
    channel_pass, channel_detail = _channel_bias_check(matched_denom, r_avg, g_avg, b_avg)

    # 11. Serial number deep check
    serial_deep_pass, serial_deep_detail = _serial_number_check(orig_img)

    # 12. Aspect ratio
    aspect_pass, aspect_detail = _aspect_ratio_check(orig_img)

    checks = {
        "color_profile_match": {
            "pass": color_check_pass,
            "detail": f"closest denomination ₹{matched_denom}, distance {round(color_dist,1)}"
        },
        "channel_color_ratio": {
            "pass": channel_pass,
            "detail": channel_detail
        },
        "fine_line_detail_proxy": {
            "pass": edge_check_pass,
            "detail": f"edge density score {round(edge_density,1)}"
        },
        "microprint_sharpness_proxy": {
            "pass": variance_check_pass,
            "detail": f"print variance {round(variance,1)}"
        },
        "security_thread_proxy": {
            "pass": thread_check_pass,
            "detail": f"vertical thread score {round(thread_score,2)}"
        },
        "clean_note_frame": {
            "pass": clean_frame_pass,
            "detail": "no stock/watermark border" if clean_frame_pass else f"suspicious border: {', '.join(strip_hits)}"
        },
        "serial_layout_sanity": {
            "pass": serial_check_pass,
            "detail": "serial placement OK" if serial_check_pass else "repeated oversized serial-like dark blocks"
        },
        "serial_number_authenticity": {
            "pass": serial_deep_pass,
            "detail": serial_deep_detail
        },
        "note_not_flat_print": {
            "pass": bright_pass,
            "detail": bright_detail
        },
        "guilloche_background_complexity": {
            "pass": guilloche_pass,
            "detail": guilloche_detail
        },
        "aspect_ratio_valid": {
            "pass": aspect_pass,
            "detail": aspect_detail
        },
        "claimed_denomination_match": {
            "pass": denomination_check_pass,
            "detail": f"claimed {claimed_denomination or '-'}, detected ₹{matched_denom}"
        },
    }

    passed = sum(1 for c in checks.values() if c["pass"])
    total = len(checks)
    confidence = round((passed / total) * 100, 1)

    # HARD FAIL: any one strong forgery signal alone is conclusive
    strong_forgery_signals = [
        not serial_deep_pass,        # zero/identical serials = specimen/toy note
        not bright_pass,             # flat-print / plain-paper print
        not guilloche_pass,          # background too uniform = no security printing
        not clean_frame_pass,        # stock-image watermark border
        not denomination_check_pass, # claimed denom doesn't match detected color
        (not channel_pass and not color_check_pass),  # both color checks fail together
    ]
    any_strong_fail = any(strong_forgery_signals)

    core_pass = (color_check_pass and edge_check_pass and variance_check_pass
                 and thread_check_pass and bright_pass and guilloche_pass
                 and serial_deep_pass and channel_pass)

    if any_strong_fail or passed <= int(total * 0.55):
        verdict = "LIKELY_COUNTERFEIT"
    elif core_pass and passed >= int(total * 0.9):
        verdict = "LIKELY_GENUINE"
    else:
        verdict = "NEEDS_MANUAL_REVIEW"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "detected_denomination": f"₹{matched_denom}",
        "claimed_denomination": claimed_denomination,
        "checks": checks,
        "forgery_signals_triggered": [
            label for label, triggered in [
                ("zero_or_identical_serial_numbers", not serial_deep_pass),
                ("flat_plain_paper_print", not bright_pass),
                ("no_guilloche_security_background", not guilloche_pass),
                ("stock_image_watermark_border", not clean_frame_pass),
                ("denomination_mismatch", not denomination_check_pass),
                ("color_channel_anomaly", not channel_pass),
            ] if triggered
        ],
        "disclaimer": "Heuristic demo analysis — not a substitute for RBI-certified note authentication.",
    }


def analyze_note_b64(b64_string: str, claimed_denomination: str = None):
    try:
        if "," in b64_string:
            b64_string = b64_string.split(",", 1)[1]
        raw = base64.b64decode(b64_string)
    except Exception as e:
        return {"verdict": "INVALID_IMAGE", "confidence": 0, "message": f"Bad base64: {e}"}
    return analyze_note(raw, claimed_denomination)


if __name__ == "__main__":
    import sys
    if not PIL_AVAILABLE:
        print("Pillow not available.")
        sys.exit(1)
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if path:
        with open(path, "rb") as f:
            result = analyze_note(f.read(), claimed_denomination=sys.argv[2] if len(sys.argv) > 2 else None)
        import json
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        # Quick smoke test with a plain yellow rectangle (should fail)
        img = Image.new("RGB", (400, 200), (210, 200, 130))
        buf = io.BytesIO(); img.save(buf, format="PNG")
        import json
        print(json.dumps(analyze_note(buf.getvalue(), "20"), indent=2, ensure_ascii=False))
