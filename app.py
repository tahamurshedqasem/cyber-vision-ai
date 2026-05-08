from flask import Flask, request, jsonify
import joblib
import pandas as pd
import numpy as np
from scapy.all import rdpcap
import os

app = Flask(__name__)

# Load model
model = joblib.load("models/random_forest_model.pkl")

print("Model loaded ✅")

# ===============================
# PCAP FEATURE EXTRACTOR
# ===============================

def extract_features_from_pcap(pcap_file):

    packets = rdpcap(pcap_file)

    dur = 0
    spkts = len(packets)
    sbytes = 0
    proto = 0

    if spkts > 0:
        dur = packets[-1].time - packets[0].time

    for pkt in packets:
        sbytes += len(pkt)
        if pkt.haslayer("TCP"):
            proto = 1
        elif pkt.haslayer("UDP"):
            proto = 2
        else:
            proto = 0

    rate = sbytes / dur if dur > 0 else 0

    # Create dictionary matching training features
    features = {
        "dur": dur,
        "proto": proto,
        "spkts": spkts,
        "sbytes": sbytes,
        "rate": rate
    }

    return features


# ===============================
# PCAP Upload Endpoint
# ===============================

@app.route("/predict-pcap", methods=["POST"])
def predict_pcap():

    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    filepath = "temp.pcap"
    file.save(filepath)

    try:
        features = extract_features_from_pcap(filepath)

        df = pd.DataFrame([features])

        # Align features with model
        model_features = model.feature_names_in_

        for col in model_features:
            if col not in df.columns:
                df[col] = 0

        df = df[model_features]

        prediction = model.predict(df)[0]
        probability = model.predict_proba(df)[0]
        confidence = float(np.max(probability))

        label = "Attack" if prediction == 1 else "Normal"

        os.remove(filepath)

        return jsonify({
            "prediction": label,
            "confidence": round(confidence, 4),
            "extracted_features": features
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/")
def home():
    return "PCAP Intrusion Detection API Running 🚀"


if __name__ == "__main__":
    app.run(debug=True)