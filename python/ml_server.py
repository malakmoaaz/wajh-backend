"""
WAJH ML Inference Server
=========================
Run: uvicorn ml_server:app --port 5001 --reload
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import numpy as np, joblib, json, math

app = FastAPI(title="WAJH ML Server")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

model      = joblib.load("wajh_model.joblib")
with open("label_map.json")    as f: LABEL_MAP     = json.load(f)
with open("landmark_ids.json") as f: LANDMARK_IDS  = json.load(f)
with open("model_stats.json")  as f: MODEL_STATS   = json.load(f)

PHI = 1.618033988749895
CONFIDENCE_THRESHOLD = 0.60  # improvement #3

class LM(BaseModel):
    id: str
    x: float
    y: float
    name: Optional[str] = ""

class PredictRequest(BaseModel):
    landmarks: List[LM]
    calibration: Optional[dict] = None
    goldenRatio: Optional[bool] = False

def rule_engine(lms: dict) -> str:
    """Improvement #4 — rule engine for ensemble."""
    def get(name, attr='x'):
        l = lms.get(name)
        return getattr(l, attr, 0) if l else 0

    pog_x  = get('pogonion', 'x')
    nas_x  = get('nasion',   'x')
    chin_x = get('chin_mid', 'x')
    sub_y  = get('subnasale','y')
    lab_y  = get('labrale_superius','y')
    gon_l  = get('gonion_l', 'x')
    gon_r  = get('gonion_r', 'x')
    gna_y  = get('gnathion', 'y')
    nas_y  = get('nasion',   'y')
    sub2_y = get('subnasale','y')

    chin_proj  = pog_x - nas_x
    jaw_width  = gon_r - gon_l
    vert_excess= sub_y - lab_y if sub_y and lab_y else 0
    lower_fh   = gna_y - sub2_y if gna_y and sub2_y else 65

    if chin_proj < -10:
        if abs(chin_x - nas_x) > 15: return "3"
        return "1"
    if chin_proj > 10: return "2"
    if lower_fh > 80:  return "5"
    if abs(chin_x - nas_x) > 12 and chin_proj > -5: return "6"
    return "0"

def golden_ratio(lms: dict, px_per_mm=None):
    scale = px_per_mm or 5.0
    def d(a, b):
        la, lb = lms.get(a), lms.get(b)
        if not la or not lb: return None
        return math.hypot(la.x-lb.x, la.y-lb.y) / scale

    lfh = d('subnasale','gnathion')
    ufh = d('nasion','subnasale')
    results = {}
    if lfh and ufh and ufh > 0:
        ratio = lfh/ufh
        results['face_height_ratio'] = {
            'current': round(ratio,3), 'ideal': round(PHI,3),
            'deviation_mm': round(abs(ratio-PHI)*ufh,1),
            'label': 'Lower / Upper Face Height',
            'within_norm': abs(ratio-PHI) < 0.15
        }
    fw = d('zygion_l','zygion_r')
    jw = d('gonion_l','gonion_r')
    if fw and jw and fw > 0:
        ratio = jw/fw
        ideal = 1/PHI
        results['jaw_face_width_ratio'] = {
            'current': round(ratio,3), 'ideal': round(ideal,3),
            'deviation_mm': round(abs(ratio-ideal)*fw,1),
            'label': 'Jaw Width / Face Width',
            'within_norm': abs(ratio-ideal) < 0.08
        }
    devs = [v['deviation_mm'] for v in results.values()]
    score = max(0, min(100, round(100 - sum(devs)/len(devs)*4))) if devs else 100
    return {
        'ratios': results,
        'harmonyScore': score,
        'overallAssessment': (
            'Excellent facial harmony' if score >= 85 else
            'Good harmony with minor deviations' if score >= 70 else
            'Moderate deviations — surgical correction may improve harmony' if score >= 50 else
            'Significant deviations from golden ratio'
        )
    }

@app.post("/ml/predict")
async def predict(req: PredictRequest):
    try:
        lms = {l.id: l for l in req.landmarks}

        # Build 90-feature vector in exact landmark order
        features = []
        for lid in LANDMARK_IDS:
            lm = lms.get(lid)
            features.append(lm.x if lm else 0.0)
            features.append(lm.y if lm else 0.0)

        X = np.array(features).reshape(1, -1)
        pred_idx = int(model.predict(X)[0])
        proba    = model.predict_proba(X)[0]
        ml_conf  = float(proba[pred_idx])

        # Improvement #4 — ensemble with rule engine
        rule_pred = rule_engine(lms)
        rule_idx  = int(rule_pred)
        both_agree = (pred_idx == rule_idx)

        # Final decision
        if both_agree:
            final_idx  = pred_idx
            final_conf = min(1.0, ml_conf + 0.05)  # boost when both agree
            source     = "ml+rules (ensemble)"
        else:
            # ML wins if high confidence, else rule engine
            if ml_conf >= 0.70:
                final_idx  = pred_idx
                final_conf = ml_conf
                source     = "ml_model"
            else:
                final_idx  = rule_idx
                final_conf = 0.60
                source     = "rule_engine"

        # Improvement #3 — confidence threshold
        if final_conf < CONFIDENCE_THRESHOLD:
            return {
                "procedure":     "Insufficient Data — Please drag more landmarks",
                "procedureId":   -1,
                "confidence":    "low",
                "confidencePct": round(final_conf * 100, 1),
                "insufficient":  True,
                "message":       "Move at least 3-4 key landmarks (chin, jaw, gonion) to get a recommendation.",
                "goldenRatio":   golden_ratio(lms, req.calibration.get('pixelsPerMm') if req.calibration else None) if req.goldenRatio else None,
                "source":        source
            }

        top3 = sorted(enumerate(proba), key=lambda x: -x[1])[:3]

        return {
            "procedure":     LABEL_MAP[str(final_idx)],
            "procedureId":   final_idx,
            "confidence":    "high" if final_conf > 0.80 else "medium" if final_conf > 0.65 else "low",
            "confidencePct": round(final_conf * 100, 1),
            "insufficient":  False,
            "bothAgree":     both_agree,
            "top3":          [{"procedure": LABEL_MAP[str(i)], "probability": round(float(p)*100,1)} for i,p in top3],
            "goldenRatio":   golden_ratio(lms, req.calibration.get('pixelsPerMm') if req.calibration else None) if req.goldenRatio else None,
            "source":        source,
            "modelStats":    MODEL_STATS
        }
    except Exception as e:
        return {"error": str(e), "procedure": "Analysis failed", "confidence": "low"}

@app.get("/ml/health")
async def health():
    return {"status": "ok", "accuracy": MODEL_STATS.get("accuracy"), "f1": MODEL_STATS.get("f1_macro")}
