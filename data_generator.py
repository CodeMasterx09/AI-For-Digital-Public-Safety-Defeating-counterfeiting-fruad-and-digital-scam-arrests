"""
Synthetic data generator — zero external dependencies.
Produces fake fraud entities/relationships (with seeded clusters) and
geo-tagged incident points across sample Indian districts for the demo.
"""
import random
import string

random.seed(42)

DENOMS = ["UPI_ID", "PHONE", "DEVICE_ID", "BANK_ACC"]

def _rand_id(prefix, n=8):
    return prefix + "_" + "".join(random.choices(string.digits, k=n))

def generate_fraud_graph(num_clusters=4, cluster_size=6, noise_entities=20):
    nodes, edges = [], []

    for c in range(num_clusters):
        cluster_nodes = []
        for _ in range(cluster_size):
            kind = random.choice(DENOMS)
            nid = _rand_id(kind)
            nodes.append({"id": nid, "type": kind})
            cluster_nodes.append(nid)
        for i in range(len(cluster_nodes)):
            for j in range(i + 1, len(cluster_nodes)):
                if random.random() < 0.45:
                    edges.append({
                        "source": cluster_nodes[i],
                        "target": cluster_nodes[j],
                        "weight": round(random.uniform(0.5, 1.0), 2),
                        "relation": random.choice(["shared_device", "txn_link", "same_call_batch"]),
                    })

    noise_nodes = []
    for _ in range(noise_entities):
        kind = random.choice(DENOMS)
        nid = _rand_id(kind)
        nodes.append({"id": nid, "type": kind})
        noise_nodes.append(nid)

    all_ids = [n["id"] for n in nodes]
    for nid in noise_nodes:
        if random.random() < 0.25:
            other = random.choice(all_ids)
            if other != nid:
                edges.append({
                    "source": nid, "target": other,
                    "weight": round(random.uniform(0.1, 0.35), 2),
                    "relation": "weak_link",
                })

    return nodes, edges

# Sample district centroids (approx, for demo only)
DISTRICTS = [
    {"name": "Thane",      "lat": 19.2183, "lon": 72.9781},
    {"name": "Mumbai",     "lat": 19.0760, "lon": 72.8777},
    {"name": "Pune",       "lat": 18.5204, "lon": 73.8567},
    {"name": "Nagpur",     "lat": 21.1458, "lon": 79.0882},
    {"name": "Nashik",     "lat": 19.9975, "lon": 73.7898},
    {"name": "Aurangabad", "lat": 19.8762, "lon": 75.3433},
]

INCIDENT_TYPES = ["fraud_complaint", "counterfeit_seizure", "cybercrime_report"]

def generate_geo_incidents(n=140):
    """Synthetic incident points jittered around district centroids, with
    a couple of districts deliberately over-weighted to form hotspots."""
    hotspot_weights = {"Thane": 3.0, "Mumbai": 2.2, "Nagpur": 1.6}
    points = []
    for _ in range(n):
        d = random.choices(
            DISTRICTS,
            weights=[hotspot_weights.get(d["name"], 1.0) for d in DISTRICTS],
        )[0]
        points.append({
            "district": d["name"],
            "lat": d["lat"] + random.uniform(-0.18, 0.18),
            "lon": d["lon"] + random.uniform(-0.18, 0.18),
            "type": random.choice(INCIDENT_TYPES),
            "severity": random.choice([1, 1, 2, 2, 3]),  # skew toward lower severity
        })
    return points


# ---------------- Time-series incident generation (for forecasting) -------
# Deliberate trend shapes per district over a 60-day window, so the
# forecasting module has a *real* pattern to detect rather than pure noise:
#   - Thane:  exponential ramp-up, already escalating (established emerging hotspot)
#   - Nagpur: the SAME ramp shape as Thane, but shifted ~16 days later
#             (i.e. an early-stage signature that should match Thane's history)
#   - Mumbai: high but flat/plateaued (already a known hotspot, NOT accelerating)
#   - Pune/Nashik/Aurangabad: low, flat, noisy baseline (nothing going on)

def _daily_rate(district, day, total_days):
    if district == "Thane":
        # exponential ramp from ~0.3/day to ~3.2/day over the window
        t = day / total_days
        return 0.3 + 2.9 * (t ** 2.2)
    if district == "Nagpur":
        # same shape as Thane, shifted later by 16 days (clip negative t to 0)
        shifted_day = max(0, day - 16)
        t = shifted_day / total_days
        return 0.25 + 2.6 * (t ** 2.2)
    if district == "Mumbai":
        return 2.0 + random.uniform(-0.2, 0.2)  # flat, established
    if district == "Pune":
        return 0.7
    if district == "Nashik":
        return 0.5
    if district == "Aurangabad":
        return 0.55
    return 0.4


def generate_geo_incidents_timeseries(days=60):
    """Day-by-day synthetic incidents per district with deliberate trend
    shapes baked in (see _daily_rate). Returns a flat list of incidents,
    each tagged with an ISO date string, ready for daily aggregation."""
    from datetime import date, timedelta
    points = []
    today = date.today()
    for day in range(days):
        the_date = (today - timedelta(days=(days - 1 - day))).isoformat()
        for d in DISTRICTS:
            rate = _daily_rate(d["name"], day, days)
            # gaussian jitter around the true rate, kept tight enough that
            # the underlying trend stays detectable rather than drowned in noise
            count = max(0, round(random.gauss(rate, max(0.12, rate * 0.18))))
            for _ in range(count):
                points.append({
                    "district": d["name"],
                    "lat": d["lat"] + random.uniform(-0.18, 0.18),
                    "lon": d["lon"] + random.uniform(-0.18, 0.18),
                    "type": random.choice(INCIDENT_TYPES),
                    "severity": random.choice([1, 1, 2, 2, 3]),
                    "date": the_date,
                })
    return points

if __name__ == "__main__":
    n, e = generate_fraud_graph()
    g = generate_geo_incidents()
    print(f"nodes={len(n)} edges={len(e)} geo_points={len(g)}")
