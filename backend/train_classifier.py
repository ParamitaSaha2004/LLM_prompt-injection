import os
import re
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# Fallback-safe imports
try:
    from sentence_transformers import SentenceTransformer
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False


def train_pipeline():
    print("Starting PromptShield ML training pipeline...")
    
    # Define paths
    dataset_path = "data/promptshield_dataset_10000.csv"
    metrics_path = "data/evaluation_metrics.csv"
    cm_plot_path = "data/confusion_matrix.png"
    perf_plot_path = "data/class_performance.png"
    
    model_dir = "models"
    model_path = os.path.join(model_dir, "promptshield_model.joblib")
    encoder_path = os.path.join(model_dir, "label_encoder.joblib")
    
    os.makedirs(model_dir, exist_ok=True)
    
    # 1. Load Datasets
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        return
        
    df = pd.read_csv(dataset_path)
    df = df.dropna(subset=['prompt', 'label'])
    df['prompt'] = df['prompt'].astype(str)
    
    print(f"Loaded primary dataset with {len(df)} rows.")

    # Merge additional XLSX if exists
    xlsx_path = "data/direct_prompt_injection_dataset_1000.xlsx"
    if os.path.exists(xlsx_path):
        print(f"Found additional dataset at {xlsx_path}. Merging...")
        df_new = pd.read_excel(xlsx_path)
        df_new = df_new.dropna(subset=['prompt'])
        df_new['prompt'] = df_new['prompt'].astype(str)
        # Map label column
        df_new['label'] = "prompt_injection"
        # Select matching columns
        df_new_selected = df_new[['prompt', 'label']]
        # Concat
        df = pd.concat([df, df_new_selected], ignore_index=True)
        print(f"Merged datasets. New total size: {len(df)} rows.")
    else:
        print(f"No additional dataset found at {xlsx_path}. Proceeding with primary dataset.")
    
    # 2. Encode Labels
    le = LabelEncoder()
    df['label_encoded'] = le.fit_transform(df['label'])
    
    num_classes = len(le.classes_)
    print(f"Encoded {num_classes} unique classes.")
    print(f"Classes: {list(le.classes_)}")
    
    # 3. Split Data: 80% train, 10% validation, 10% test
    # First split 90% train_val and 10% test
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        df['prompt'].values, 
        df['label_encoded'].values, 
        test_size=0.10, 
        random_state=42, 
        stratify=df['label_encoded'].values
    )
    
    # Then split 90% train_val into 80% train and 10% validation (which is 1/9 of 90%)
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, 
        y_train_val, 
        test_size=1/9, 
        random_state=42, 
        stratify=y_train_val
    )
    
    print(f"Split sizes -> Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
    
    # 4. Generate Embeddings
    if not HAS_TRANSFORMERS:
        print("Error: sentence-transformers package is missing. Cannot proceed with training.")
        return
        
    print("Loading SentenceTransformer model 'all-MiniLM-L6-v2'...")
    embedder = SentenceTransformer('all-MiniLM-L6-v2')
    
    print("Generating training embeddings...")
    X_train_emb = embedder.encode(X_train.tolist(), show_progress_bar=True)
    
    print("Generating validation embeddings...")
    X_val_emb = embedder.encode(X_val.tolist(), show_progress_bar=True)
    
    print("Generating test embeddings...")
    X_test_emb = embedder.encode(X_test.tolist(), show_progress_bar=True)
    
    # 5. Train & Compare Models
    models_to_compare = {}
    
    # 5a. Logistic Regression
    print("Training Logistic Regression classifier...")
    lr_clf = LogisticRegression(max_iter=1000, C=1.0, random_state=42)
    lr_clf.fit(X_train_emb, y_train)
    y_val_pred_lr = lr_clf.predict(X_val_emb)
    
    lr_acc = accuracy_score(y_val, y_val_pred_lr)
    lr_f1 = f1_score(y_val, y_val_pred_lr, average='weighted')
    print(f"Logistic Regression Validation -> Accuracy: {lr_acc:.4f}, Weighted F1: {lr_f1:.4f}")
    models_to_compare["Logistic Regression"] = {"model": lr_clf, "f1": lr_f1, "acc": lr_acc}
    
    # 5b. XGBoost
    if HAS_XGB:
        print("Training XGBoost classifier...")
        xgb_clf = XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42)
        xgb_clf.fit(X_train_emb, y_train)
        y_val_pred_xgb = xgb_clf.predict(X_val_emb)
        
        xgb_acc = accuracy_score(y_val, y_val_pred_xgb)
        xgb_f1 = f1_score(y_val, y_val_pred_xgb, average='weighted')
        print(f"XGBoost Validation -> Accuracy: {xgb_acc:.4f}, Weighted F1: {xgb_f1:.4f}")
        models_to_compare["XGBoost"] = {"model": xgb_clf, "f1": xgb_f1, "acc": xgb_acc}
    else:
        print("XGBoost package is not installed. Skipping XGBoost training.")
        
    # Choose best model
    best_name = max(models_to_compare.keys(), key=lambda k: models_to_compare[k]["f1"])
    best_model = models_to_compare[best_name]["model"]
    print(f"\nWinner: {best_name} (Validation F1: {models_to_compare[best_name]['f1']:.4f})")
    
    # 6. Evaluate Winner on Test Set
    print(f"Evaluating best model ({best_name}) on test set...")
    y_test_pred = best_model.predict(X_test_emb)
    
    test_acc = accuracy_score(y_test, y_test_pred)
    test_prec_w = precision_score(y_test, y_test_pred, average='weighted')
    test_rec_w = recall_score(y_test, y_test_pred, average='weighted')
    test_f1_w = f1_score(y_test, y_test_pred, average='weighted')
    
    test_prec_m = precision_score(y_test, y_test_pred, average='macro')
    test_rec_m = recall_score(y_test, y_test_pred, average='macro')
    test_f1_m = f1_score(y_test, y_test_pred, average='macro')
    
    print("\n" + "="*40)
    print(f"TEST EVALUATION RESULTS ({best_name})")
    print("="*40)
    print(f"Accuracy:        {test_acc:.4f}")
    print(f"Precision (W):   {test_prec_w:.4f}  |  (Macro): {test_prec_m:.4f}")
    print(f"Recall (W):      {test_rec_w:.4f}  |  (Macro): {test_rec_m:.4f}")
    print(f"F1-Score (W):    {test_f1_w:.4f}  |  (Macro): {test_f1_m:.4f}")
    print("="*40)
    
    # Save Model & Label Encoder
    joblib.dump(best_model, model_path)
    joblib.dump(le, encoder_path)
    print(f"Saved best model to {model_path}")
    print(f"Saved label encoder to {encoder_path}")
    
    # Save detailed classification report as CSV
    report_dict = classification_report(y_test, y_test_pred, target_names=le.classes_, output_dict=True)
    
    # Append overall scores
    report_dict["overall"] = {
        "precision": test_prec_w,
        "recall": test_rec_w,
        "f1-score": test_f1_w,
        "support": len(y_test)
    }
    
    metrics_df = pd.DataFrame(report_dict).transpose()
    metrics_df.to_csv(metrics_path)
    print(f"Exported metrics report to {metrics_path}")
    
    # 7. Generate Plots
    # 7a. Confusion Matrix Heatmap
    cm = confusion_matrix(y_test, y_test_pred)
    plt.figure(figsize=(14, 12))
    sns.heatmap(cm, annot=True, fmt='d', xticklabels=le.classes_, yticklabels=le.classes_, cmap='Blues')
    plt.title(f"Confusion Matrix - {best_name} on Test Set")
    plt.ylabel('Actual Label')
    plt.xlabel('Predicted Label')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(cm_plot_path, dpi=150)
    plt.close()
    print(f"Saved confusion matrix plot to {cm_plot_path}")
    
    # 7b. F1-Score per Class bar chart
    class_names = list(le.classes_)
    class_f1s = [report_dict[c]['f1-score'] for c in class_names]
    
    plt.figure(figsize=(14, 7))
    bars = plt.bar(class_names, class_f1s, color=plt.cm.viridis(np.linspace(0, 1, len(class_names))))
    plt.title(f"F1-Score per Class - {best_name} on Test Set")
    plt.ylabel('F1-Score')
    plt.xlabel('Class Label')
    plt.xticks(rotation=45, ha='right')
    plt.ylim(0, 1.05)
    
    # Add values on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width()/2.0, 
            height + 0.01, 
            f'{height:.2f}', 
            ha='center', 
            va='bottom', 
            fontsize=9
        )
        
    plt.tight_layout()
    plt.savefig(perf_plot_path, dpi=150)
    plt.close()
    print(f"Saved class performance plot to {perf_plot_path}")
    print("ML Pipeline completed successfully!")


if __name__ == "__main__":
    train_pipeline()
