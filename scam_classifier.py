"""
Scam Message Classifier + Digital Arrest Call-Flow Scorer.
Zero hard dependencies (pure stdlib regex/heuristics). Optionally enriches
with Claude (only if `anthropic` package + ANTHROPIC_API_KEY are present) —
falls back gracefully otherwise so the demo always works offline.

Multilingual support:
  - Hindi/Marathi/Gujarati scam keywords scored natively (no translation needed)
  - When ANTHROPIC_API_KEY is set, non-English text is translated first, then
    classified — so the LLM reasoning always runs on English regardless of input
"""
import os
import re
import json

# ---------------- Layer 1: message/script red flags ----------------------
# English patterns
RED_FLAGS = {
    r"\b(cbi|police|customs|narcotics|enforcement directorate|\bed\b)\b": 25,
    r"\b(digital arrest|arrest warrant|legal action)\b": 30,
    r"\b(video call|join.{0,15}call)\b": 15,
    r"\b(freeze|frozen|block.{0,10}account)\b": 20,
    r"\b(otp|one time password)\b": 20,
    r"\b(urgent|immediately|within \d+ minutes|right now)\b": 15,
    r"\b(transfer|deposit|pay).{0,20}(verification|safekeeping|escrow)\b": 25,
    r"\b(aadhaar|pan card|kyc).{0,20}(suspend|block|link)\b": 20,
    r"\bdo not (tell|inform|disclose).{0,15}(family|anyone|bank)\b": 25,
    r"\bparcel|courier\b.{0,20}\bdrugs|illegal\b": 20,
}

# Hindi / Marathi / Gujarati scam keyword patterns (Devanagari + transliteration)
RED_FLAGS_MULTILINGUAL = {
    # "CBI / police" in Hindi
    r"(सीबीआई|पुलिस|साइबर सेल|प्रवर्तन निदेशालय)": 25,
    # "arrest" / "warrant" in Hindi
    r"(गिरफ्तार|वारंट|कानूनी कार्रवाई|डिजिटल अरेस्ट)": 30,
    # "video call" in Hindi/transliteration
    r"(वीडियो कॉल|video call करें)": 15,
    # "freeze / block account" in Hindi
    r"(खाता बंद|अकाउंट फ्रीज|बैंक खाता)": 20,
    # "OTP" in Hindi context
    r"(ओटीपी|otp बताएं|otp share)": 20,
    # urgency words Hindi
    r"(तुरंत|अभी|फौरन|जल्दी करें)": 15,
    # payment demand in Hindi
    r"(पैसे ट्रांसफर|भुगतान करें|जमानत राशि)": 25,
    # Aadhaar/PAN scam Hindi
    r"(आधार|पैन कार्ड|केवाईसी).{0,20}(बंद|ब्लॉक|लिंक)": 20,
    # "don't tell family" Hindi
    r"(परिवार को मत बताना|किसी को न बताएं)": 25,
    # parcel/drugs Hindi
    r"(पार्सल|कूरियर).{0,20}(ड्रग्स|नशा|अवैध)": 20,
    # Marathi: "police / CBI" common transliterations
    r"(पोलीस|सीबीआय|सायबर सेल)": 25,
    # Marathi urgency
    r"(ताबडतोब|लगेच|त्वरित)": 15,
}


def rule_based_score(text: str):
    text_l = text.lower()
    score, triggered = 0, []
    for pattern, weight in RED_FLAGS.items():
        if re.search(pattern, text_l):
            score += weight
            triggered.append(pattern)
    # Multilingual — run on original text (preserves Devanagari)
    for pattern, weight in RED_FLAGS_MULTILINGUAL.items():
        if re.search(pattern, text):
            score += weight
            triggered.append(pattern)
    return min(score, 100), triggered


def verdict_from_score(score: int):
    if score >= 60:
        return "SCAM_LIKELY"
    if score >= 30:
        return "SUSPICIOUS"
    return "LIKELY_SAFE"


ADVICE = {
    "SCAM_LIKELY": (
        "This strongly matches a known 'digital arrest' / impersonation scam pattern. "
        "Do NOT transfer money or share OTP/KYC details. Hang up. Real police/CBI never "
        "make arrests or demand payment over a phone/video call. Report via the Cyber "
        "Crime helpline 1930 or cybercrime.gov.in."
    ),
    "SUSPICIOUS": (
        "Several risk indicators are present. Verify independently by calling the "
        "organisation back using an officially listed number. Do not share OTP, "
        "passwords, or make any payment until verified."
    ),
    "LIKELY_SAFE": (
        "No strong scam indicators detected. Still avoid sharing sensitive financial "
        "details with unverified callers."
    ),
}


def _translate_to_english(text: str, api_key: str) -> str:
    """Translate text to English using Claude. Returns original text on failure."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model="claude-sonnet-4-6", max_tokens=500,
            messages=[{
                "role": "user",
                "content": (
                    "Translate the following text to English. "
                    "If it is already in English, return it unchanged. "
                    "Return ONLY the translated text, no explanation.\n\n"
                    f"Text: {text}"
                )
            }]
        )
        return resp.content[0].text.strip()
    except Exception:
        return text   # fallback: use original


def llm_classify(text: str, language: str = "en"):
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)

        # Translate non-English input before LLM classification
        english_text = text
        translated = False
        if language != "en":
            english_text = _translate_to_english(text, api_key)
            translated = english_text.lower() != text.lower()

        prompt = (
            "You are a fraud-detection classifier for an Indian citizen safety app.\n"
            "Classify this message as SCAM_LIKELY, SUSPICIOUS, or LIKELY_SAFE, "
            "considering digital-arrest scams, KYC/OTP phishing, fake police/CBI calls, "
            "parcel/courier drug scams, and any financial coercion tactics common in India.\n"
            'Respond ONLY as JSON: {"verdict":"...","confidence":0-100,"reasoning":"...","advice":"..."}\n\n'
            f'Message: """{english_text}"""'
        )
        resp = client.messages.create(
            model="claude-sonnet-4-6", max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = resp.content[0].text.strip()
        raw = re.sub(r"^```json|```$", "", raw).strip()
        result = json.loads(raw)
        if translated:
            result["translated_from"] = language
            result["translated_text"] = english_text
        return result
    except Exception as e:
        return {"error": str(e)}


def classify(text: str, language: str = "en"):
    score, triggered = rule_based_score(text)
    rule_verdict = verdict_from_score(score)
    result = {
        "input": text,
        "rule_based": {"score": score, "verdict": rule_verdict, "triggered_patterns": len(triggered)},
        "verdict": rule_verdict,
        "confidence": score,
        "advice": ADVICE[rule_verdict],
        "source": "rule_based",
        "language": language,
    }
    llm_result = llm_classify(text, language=language)
    if llm_result and "error" not in llm_result:
        result["llm"] = llm_result
        result["verdict"]    = llm_result.get("verdict", rule_verdict)
        result["confidence"] = llm_result.get("confidence", score)
        result["advice"]     = llm_result.get("advice", result["advice"])
        result["source"]     = "rule_based+llm"
        if "translated_from" in llm_result:
            result["translated_from"] = llm_result["translated_from"]
            result["translated_text"] = llm_result.get("translated_text", "")
    return result

# ---------------- Layer 2: call-flow / metadata scorer ---------------------
# Digital Arrest Scam Detection module: scores live call signals rather than
# just transcript text — number spoofing signatures, video-call demand, etc.

SUSPICIOUS_PREFIXES = ("+92", "+1", "+44", "140", "0140")  # illustrative demo list only

def score_call_metadata(meta: dict):
    """
    meta: {
      caller_number: str, duration_sec: int, is_video_call: bool,
      claimed_authority: str, multiple_recipients: bool, demanded_payment: bool
    }
    """
    score, flags = 0, []
    num = str(meta.get("caller_number", ""))
    if any(num.startswith(p) for p in SUSPICIOUS_PREFIXES):
        score += 20; flags.append("spoofed_number_pattern")
    if meta.get("is_video_call"):
        score += 15; flags.append("unsolicited_video_call")
    if meta.get("claimed_authority", "").lower() in {"cbi", "police", "customs", "ed", "narcotics"}:
        score += 25; flags.append("authority_impersonation_claim")
    if meta.get("duration_sec", 0) > 900:
        score += 10; flags.append("prolonged_call_isolation_pattern")
    if meta.get("demanded_payment"):
        score += 30; flags.append("payment_demand_during_call")
    score = min(score, 100)
    return {
        "metadata_risk_score": score,
        "flags": flags,
        "verdict": verdict_from_score(score),
    }

if __name__ == "__main__":
    print(classify("Sir this is CBI cyber cell, your Aadhaar is linked to drugs parcel, join video call now or face arrest warrant"))
    print(score_call_metadata({
        "caller_number": "+92123456", "is_video_call": True,
        "claimed_authority": "CBI", "duration_sec": 1200, "demanded_payment": True
    }))
