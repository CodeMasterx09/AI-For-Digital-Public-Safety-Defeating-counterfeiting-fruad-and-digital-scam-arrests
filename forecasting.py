"""
District Risk Forecasting — predictive layer on top of the geospatial data.

This is what turns the platform from "here's where fraud happened" into
"here's where it's about to spike, and here's the district whose pattern
it's repeating." Built entirely on pure-Python stats (no numpy/pandas) so
it stays zero-dependency like the rest of the backend.

Method (deliberately simple and explainable, not a black box):
  1. Aggregate incidents into daily counts per district.
  2. Compare the most recent window (e.g. last 7 days) average against the
     prior window of the same length -> growth rate.
  3. Classify into EMERGING_HOTSPOT / RISING / STABLE / DECLINING / LOW_ACTIVITY.
  4. For accelerating districts, search every OTHER district's full history
     for the most similar-shaped window (Pearson correlation on normalized
     curves) -> "this looks like District X's pattern N days ago."
  5. Rank by a priority score that rewards acceleration, not just raw volume
     -- a small-but-fast-growing district can outrank a large-but-flat one.
"""
from datetime import date, timedelta
import math


def daily_series(incidents, district, days=60):
    """Returns a list of (date_str, count) for the given district, every day
    in the window, zero-filled for days with no incidents."""
    today = date.today()
    counts = {}
    for inc in incidents:
        if inc.get("district") != district or "date" not in inc:
            continue
        counts[inc["date"]] = counts.get(inc["date"], 0) + 1
    series = []
    for d in range(days):
        the_date = (today - timedelta(days=(days - 1 - d))).isoformat()
        series.append((the_date, counts.get(the_date, 0)))
    return series


def _avg(values):
    return sum(values) / len(values) if values else 0.0


def _growth_rate(series, window=7):
    """Compares the most recent `window` days vs the `window` days before that."""
    counts = [c for _, c in series]
    if len(counts) < window * 2:
        window = max(1, len(counts) // 2)
    recent = counts[-window:]
    prior = counts[-2 * window:-window] if len(counts) >= 2 * window else counts[:window]
    recent_avg, prior_avg = _avg(recent), _avg(prior)
    if prior_avg == 0:
        growth = 1.0 if recent_avg > 0 else 0.0  # from-zero growth, capped
    else:
        growth = (recent_avg - prior_avg) / prior_avg
    return round(growth, 3), round(recent_avg, 2), round(prior_avg, 2)


def classify_trend(growth_rate, recent_avg):
    if recent_avg < 0.6:
        return "LOW_ACTIVITY"
    if growth_rate >= 0.3 and recent_avg >= 1.5:
        return "EMERGING_HOTSPOT"
    if growth_rate >= 0.12:
        return "RISING"
    if growth_rate <= -0.15:
        return "DECLINING"
    return "STABLE"


def _normalize(values):
    m = max(values) if values and max(values) > 0 else 1
    return [v / m for v in values]


def _pearson(a, b):
    n = len(a)
    if n == 0 or n != len(b):
        return 0.0
    ma, mb = _avg(a), _avg(b)
    num = sum((a[i] - ma) * (b[i] - mb) for i in range(n))
    da = math.sqrt(sum((x - ma) ** 2 for x in a))
    db = math.sqrt(sum((x - mb) ** 2 for x in b))
    if da == 0 or db == 0:
        return 0.0
    return num / (da * db)


def find_historical_analog(target_district, all_series, window=10, min_correlation=0.55):
    """
    Slides a `window`-day frame across every OTHER district's history and
    finds the best-correlated match to the target district's most recent
    `window` days. Returns the matching district, how many days ago that
    window ended, and the correlation -- or None if nothing matches well.
    """
    target_counts = [c for _, c in all_series[target_district][-window:]]
    target_norm = _normalize(target_counts)
    if sum(target_counts) == 0:
        return None

    best = None
    for district, series in all_series.items():
        if district == target_district:
            continue
        counts = [c for _, c in series]
        if len(counts) < window:
            continue
        for end in range(window, len(counts) + 1):
            frame = counts[end - window:end]
            if sum(frame) == 0:
                continue
            corr = _pearson(target_norm, _normalize(frame))
            if best is None or corr > best["correlation"]:
                lag_days = len(counts) - end  # how many days ago this window ended
                best = {"district": district, "correlation": round(corr, 2), "lag_days": lag_days}
    if best and best["correlation"] >= min_correlation:
        return best
    return None


def forecast_districts(incidents, districts, days=60, recent_window=10):
    all_series = {d["name"]: daily_series(incidents, d["name"], days) for d in districts}
    results = []
    for name, series in all_series.items():
        growth, recent_avg, prior_avg = _growth_rate(series, recent_window)
        trend = classify_trend(growth, recent_avg)
        analog = None
        if trend in ("EMERGING_HOTSPOT", "RISING"):
            analog = find_historical_analog(name, all_series)

        # priority score rewards acceleration, not just raw volume
        priority = round(recent_avg * (1 + max(0, growth)), 2)

        explanation = _explain(name, trend, growth, recent_avg, analog)

        results.append({
            "district": name,
            "trend": trend,
            "recent_avg_per_day": recent_avg,
            "prior_avg_per_day": prior_avg,
            "growth_rate_pct": round(growth * 100, 1),
            "priority_score": priority,
            "historical_analog": analog,
            "explanation": explanation,
            "sparkline": [c for _, c in series[-30:]],  # last 30 days for charting
        })
    results.sort(key=lambda r: r["priority_score"], reverse=True)
    return results


def _explain(district, trend, growth, recent_avg, analog):
    pct = abs(round(growth * 100))
    if trend == "EMERGING_HOTSPOT":
        base = f"{district} reports have grown {pct}% week-over-week — among the fastest-accelerating districts right now."
    elif trend == "RISING":
        base = f"{district} is trending upward, {pct}% week-over-week growth."
    elif trend == "DECLINING":
        base = f"{district} reports have dropped {pct}% week-over-week."
    elif trend == "LOW_ACTIVITY":
        base = f"{district} shows minimal recent activity ({recent_avg}/day)."
    else:
        base = f"{district} is stable at roughly {recent_avg}/day."

    if analog:
        base += (
            f" This trajectory closely matches {analog['district']}'s pattern from "
            f"{analog['lag_days']} days ago (similarity {analog['correlation']}) — "
            f"recommend pre-positioning patrol/outreach resources before it follows the same curve."
        )
    return base


if __name__ == "__main__":
    from data_generator import generate_geo_incidents_timeseries, DISTRICTS
    incidents = generate_geo_incidents_timeseries(60)
    forecasts = forecast_districts(incidents, DISTRICTS)
    for f in forecasts:
        print(f["district"], f["trend"], f"growth={f['growth_rate_pct']}%", f"priority={f['priority_score']}")
        print("   ", f["explanation"])
