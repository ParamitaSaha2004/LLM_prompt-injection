import sys
import os
import json
import joblib

# Fallback-safe imports
try:
    from sentence_transformers import SentenceTransformer
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False


def predict_prompt():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No prompt provided. Usage: python predict.py \"prompt_text\""}))
        return
        
    prompt_text = sys.argv[1]
    
    model_path = "models/promptshield_model.joblib"
    encoder_path = "models/label_encoder.joblib"
    
    if not os.path.exists(model_path) or not os.path.exists(encoder_path):
        print(json.dumps({"error": "Model files not found. Please run train_classifier.py first."}))
        return
        
    if not HAS_TRANSFORMERS:
        print(json.dumps({"error": "sentence-transformers is not installed."}))
        return
        
    # Load model and label encoder
    clf = joblib.load(model_path)
    le = joblib.load(encoder_path)
    
    # Load sentence embedder
    embedder = SentenceTransformer('all-MiniLM-L6-v2')
    
    # Embed the prompt
    emb = embedder.encode([prompt_text])
    
    # Predict probabilities and label
    probs = clf.predict_proba(emb)[0]
    
    # Support both XGBoost and Scikit-Learn prediction outputs
    if hasattr(clf, "classes_"):
        # For sklearn models (like Logistic Regression)
        pred_idx = clf.predict(emb)[0]
        predicted_label = le.inverse_transform([pred_idx])[0]
        confidence_score = float(probs[pred_idx])
        class_probs = {le.inverse_transform([i])[0]: float(probs[i]) for i in range(len(probs))}
    else:
        # Fallback if classes or indices are formatted differently (like XGBoost native)
        pred_idx = int(clf.predict(emb)[0])
        predicted_label = le.inverse_transform([pred_idx])[0]
        confidence_score = float(probs[pred_idx])
        class_probs = {le.inverse_transform([i])[0]: float(probs[i]) for i in range(len(probs))}
        
    output = {
        "predicted_label": predicted_label,
        "confidence_score": confidence_score,
        "class_probabilities": class_probs
    }
    
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    predict_prompt()
