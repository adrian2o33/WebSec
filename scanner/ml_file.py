import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

MODEL_PATH = os.path.join(os.path.dirname(__file__), "file_ml_model.joblib")

def extract_features(file_size, entropy, regex_hit_count, max_severity, is_text, printable_char_ratio, has_pe_header, is_office_doc):
    """
    Extracts a feature vector for the ML model.
    max_severity: 0=None, 1=Low, 2=Medium, 3=High, 4=Critical
    """
    return np.array([
        file_size,
        entropy,
        regex_hit_count,
        max_severity,
        1 if is_text else 0,
        printable_char_ratio,
        1 if has_pe_header else 0,
        1 if is_office_doc else 0
    ])

def train_dummy_model():
    """Trains a dummy Random Forest model on synthetic file data."""
    X = []
    y = []

    # Generate Benign samples
    for _ in range(500):
        # Benign files typically have low/medium entropy, few regex hits
        size = np.random.randint(1000, 500000)
        entropy = np.random.uniform(2.0, 6.0)
        hits = np.random.randint(0, 2)
        sev = 0 if hits == 0 else 1
        is_txt = np.random.choice([0, 1])
        printable = np.random.uniform(0.7, 1.0) if is_txt else np.random.uniform(0.1, 0.4)
        has_pe = 0
        is_doc = np.random.choice([0, 1]) if not is_txt else 0
        X.append([size, entropy, hits, sev, is_txt, printable, has_pe, is_doc])
        y.append(0) # 0 = Clean

    # Generate Malicious samples
    for _ in range(100):
        # Packed malware: high entropy, no text, PE header
        X.append([np.random.randint(10000, 100000), np.random.uniform(7.5, 8.0), 0, 0, 0, np.random.uniform(0.0, 0.2), 1, 0])
        y.append(1) # 1 = Malicious
        
        # Script malware: text, many hits, high severity, high printable char
        X.append([np.random.randint(100, 5000), np.random.uniform(4.0, 6.0), np.random.randint(3, 10), np.random.randint(3, 5), 1, np.random.uniform(0.8, 1.0), 0, 0])
        y.append(1)
        
        # Malicious Office Doc: low text, hits, high severity, is_doc
        X.append([np.random.randint(10000, 200000), np.random.uniform(5.0, 7.0), np.random.randint(1, 5), np.random.randint(2, 5), 0, np.random.uniform(0.1, 0.5), 0, 1])
        y.append(1)

    X = np.array(X)
    y = np.array(y)

    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    
    joblib.dump(model, MODEL_PATH)
    print(f"ML File model trained and saved to {MODEL_PATH}")

def predict_threat(features):
    """Returns (is_malicious: bool, confidence: float)"""
    if not os.path.exists(MODEL_PATH):
        return False, 0.0
    
    try:
        model = joblib.load(MODEL_PATH)
        pred = model.predict([features])[0]
        proba = model.predict_proba([features])[0][1]
        return bool(pred == 1), float(proba)
    except Exception as e:
        print(f"ML prediction error: {e}")
        return False, 0.0

if __name__ == "__main__":
    train_dummy_model()
