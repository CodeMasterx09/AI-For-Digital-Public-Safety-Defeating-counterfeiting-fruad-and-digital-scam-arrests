"""
Geospatial Crime Pattern Intelligence — zero external dependencies.
Bins incident points into a lat/lon grid and scores hotspot intensity,
so patrol/resource prioritization can be ranked without needing GIS libs.
"""

def compute_hotspots(points, grid_size=0.05):
    """
    points: [{lat, lon, type, severity, district}, ...]
    Bins points into grid_size-degree cells, returns ranked hotspot cells.
    """
    cells = {}
    for p in points:
        cell_key = (round(p["lat"] / grid_size), round(p["lon"] / grid_size))
        c = cells.setdefault(cell_key, {
            "lat_sum": 0, "lon_sum": 0, "count": 0, "severity_sum": 0,
            "districts": set(), "types": {},
        })
        c["lat_sum"] += p["lat"]
        c["lon_sum"] += p["lon"]
        c["count"] += 1
        c["severity_sum"] += p.get("severity", 1)
        c["districts"].add(p.get("district", "unknown"))
        c["types"][p["type"]] = c["types"].get(p["type"], 0) + 1

    hotspots = []
    for (gx, gy), c in cells.items():
        intensity = c["count"] * 1.0 + c["severity_sum"] * 0.5
        hotspots.append({
            "lat": round(c["lat_sum"] / c["count"], 4),
            "lon": round(c["lon_sum"] / c["count"], 4),
            "incident_count": c["count"],
            "severity_total": c["severity_sum"],
            "intensity": round(intensity, 1),
            "districts": list(c["districts"]),
            "type_breakdown": c["types"],
        })
    hotspots.sort(key=lambda h: h["intensity"], reverse=True)
    return hotspots


def district_summary(points):
    """Aggregate counts per district for the command-centre table view."""
    summary = {}
    for p in points:
        d = p.get("district", "unknown")
        s = summary.setdefault(d, {"district": d, "total": 0, "fraud_complaint": 0,
                                    "counterfeit_seizure": 0, "cybercrime_report": 0})
        s["total"] += 1
        s[p["type"]] += 1
    ranked = sorted(summary.values(), key=lambda s: s["total"], reverse=True)
    return ranked


if __name__ == "__main__":
    from data_generator import generate_geo_incidents
    pts = generate_geo_incidents()
    hs = compute_hotspots(pts)
    print(f"points={len(pts)} hotspot_cells={len(hs)}")
    print("Top hotspot:", hs[0])
    print("District summary:", district_summary(pts)[:3])
