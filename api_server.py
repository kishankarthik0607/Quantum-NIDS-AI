import logging
import os
from pathlib import Path
from typing import Dict, Any

# Prevent OpenBLAS Memory Allocation Errors
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

import numpy as np
import pandas as pd
import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Quantum NIDS Inference API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to extension ID
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
MODEL_PATH = BASE_DIR / "models" / "best_model.pkl"

MODEL_FEATURES = [
    "Destination_Port", "Total_Backward_Packets", "Total_Length_of_Fwd_Packets", 
    "Total_Length_of_Bwd_Packets", "Fwd_Packet_Length_Max", "Fwd_Packet_Length_Mean", 
    "Bwd_Packet_Length_Max", "Bwd_Packet_Length_Min", "Bwd_Packet_Length_Std", 
    "Flow_IAT_Std", "Flow_IAT_Max", "Fwd_IAT_Total", "Fwd_IAT_Mean", "Fwd_IAT_Max", 
    "Fwd_IAT_Min", "Bwd_IAT_Total", "Bwd_IAT_Max", "Fwd_Packets/s", "Max_Packet_Length", 
    "Packet_Length_Variance", "PSH_Flag_Count", "ACK_Flag_Count", "Avg_Fwd_Segment_Size", 
    "Subflow_Fwd_Bytes", "Subflow_Bwd_Packets", "Subflow_Bwd_Bytes", "Init_Win_bytes_backward", 
    "Active_Std", "Active_Max", "Idle_Max"
]

model = None

@app.on_event("startup")
def load_model():
    global model
    try:
        model = joblib.load(MODEL_PATH)
        logger.info("Model loaded successfully.")
    except Exception as e:
        logger.error(f"Failed to load model: {e}")

class InferenceRequest(BaseModel):
    features: Dict[str, float]

@app.post("/api/v1/predict")
async def predict(request: InferenceRequest):
    global model
    if model is None:
        load_model()
    if model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        feature_vector = []
        for feature in MODEL_FEATURES:
            feature_vector.append(request.features.get(feature, 0.0))
            
        df = pd.DataFrame([feature_vector], columns=MODEL_FEATURES)
        
        prediction = model.predict(df)[0]
        prob = 0.0
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(df)[0]
            if len(probabilities) > 1:
                prob = probabilities[1]
            else:
                prob = float(prediction)
        else:
            prob = float(prediction)

        return {
            "prediction": "ATTACK" if prediction == 1 else "BENIGN",
            "risk_score_contribution": round(prob * 100, 2),
            "status": "success"
        }

    except Exception as e:
        logger.error(f"Inference error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
