from flask import Flask, jsonify, render_template
import pandas as pd
import joblib
import numpy as np
from datetime import datetime

app = Flask(__name__, template_folder='templates')

print("\n" + "=" * 60)
print("🚀 STARTING IoT BOTNET DETECTION SERVER")
print("=" * 60)

# Load model
model = joblib.load('botnet_model.pkl')
scaler = joblib.load('scaler.pkl')
feature_columns = joblib.load('feature_columns.pkl')
df = pd.read_csv('data/iot_dataset.csv').dropna()
df = pd.get_dummies(df, drop_first=True)

print("✅ Model loaded!")
print("✅ Dataset loaded!")

predictions_cache = []

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/simulate')
def simulate():
    global predictions_cache
    
    sample = df.sample(1).copy()
    
    for col in feature_columns:
        if col not in sample.columns:
            sample[col] = 0
    
    X = sample[feature_columns]
    X_scaled = scaler.transform(X)
    
    prob = model.predict_proba(X_scaled)[0]
    threat = max(prob) * 100
    
    if threat > 80:
        status = 'CRITICAL'
    elif threat > 50:
        status = 'SUSPICIOUS'
    else:
        status = 'SAFE'
    
    rec = {
        'device_id': f"Device_{len(predictions_cache)+1}",
        'threat_level': round(threat, 2),
        'status': status,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }
    
    predictions_cache.append(rec)
    return jsonify(rec)

@app.route('/api/threats')
def threats():
    safe = sum(1 for p in predictions_cache if p['threat_level'] <= 50)
    sus = sum(1 for p in predictions_cache if 50 < p['threat_level'] <= 80)
    crit = sum(1 for p in predictions_cache if p['threat_level'] > 80)
    
    return jsonify({
        'threats': predictions_cache[-100:],
        'safe': safe,
        'suspicious': sus,
        'critical': crit
    })

@app.route('/api/clear')
def clear():
    global predictions_cache
    predictions_cache = []
    return jsonify({'ok': True})

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("📱 OPEN IN BROWSER: http://localhost:5000")
    print("=" * 60 + "\n")
    app.run(debug=False, port=5000)

    #new changing made