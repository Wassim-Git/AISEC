"""
train.py - Train XGBoost phishing detection model on PhiUSIIL dataset.

Usage:
    pip install xgboost scikit-learn pandas requests
    python train.py

Downloads dataset from Kaggle (requires kaggle API key) or uses sample data.
Saves model to models/phishing_model.pkl
"""
import os
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import LabelEncoder

try:
    import xgboost as xgb
    HAS_XGB = True
except ImportError:
    from sklearn.ensemble import GradientBoostingClassifier
    HAS_XGB = False
    print("XGBoost not installed, using sklearn GradientBoosting instead")

# Import our feature extractor
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.url_analyzer import extract_features


def generate_sample_data(n_phishing=2000, n_benign=2000):
    """
    Generate realistic sample data for training when the real dataset is unavailable.
    In production, replace this with the actual PhiUSIIL or PhishTank dataset.
    """
    import random
    import string
    
    benign_domains = [
        "google.com", "microsoft.com", "amazon.com", "github.com", "stackoverflow.com",
        "wikipedia.org", "youtube.com", "linkedin.com", "twitter.com", "reddit.com",
        "apple.com", "netflix.com", "spotify.com", "dropbox.com", "slack.com",
    ]
    
    suspicious_tlds = [".tk", ".ml", ".ga", ".xyz", ".top", ".icu", ".buzz"]
    
    urls = []
    labels = []
    
    # Generate benign URLs
    for _ in range(n_benign):
        domain = random.choice(benign_domains)
        path = "/" + "/".join(random.choices(string.ascii_lowercase, k=random.randint(1, 3)))
        urls.append(f"https://{domain}{path}")
        labels.append(0)
    
    # Generate phishing URLs
    brands = ["google", "microsoft", "paypal", "amazon", "apple", "netflix"]
    for _ in range(n_phishing):
        brand = random.choice(brands)
        tld = random.choice(suspicious_tlds)
        techniques = [
            f"https://{brand}-secure{tld}/login",
            f"https://secure-{brand}{tld}/verify",
            f"https://{brand[:4]}{''.join(random.choices(string.digits, k=4))}{tld}",
            f"https://{''.join(random.choices(string.ascii_lowercase, k=8))}{tld}/account",
            f"http://192.168.{random.randint(1,254)}.{random.randint(1,254)}/login",
            f"https://{brand}.{brand}{tld}/update",
        ]
        urls.append(random.choice(techniques))
        labels.append(1)
    
    return urls, labels


def extract_feature_vectors(urls: list) -> np.ndarray:
    """Extract feature vectors for all URLs."""
    vectors = []
    for url in urls:
        try:
            f = extract_features(url)
            vector = [
                f["url_length"],
                f["domain_length"],
                f["special_char_ratio"],
                f["digit_ratio"],
                f["hyphen_count"],
                f["dot_count"],
                f["has_at_symbol"],
                f["has_ip_address"],
                f["has_https"],
                f["subdomain_count"],
                f["suspicious_tld"],
                f["domain_entropy"],
                f["path_entropy"],
                f["query_param_count"],
                f["has_redirect_param"],
            ]
            vectors.append(vector)
        except Exception as e:
            vectors.append([0] * 15)
    return np.array(vectors, dtype=np.float32)


def train_model():
    """Main training function."""
    print("=" * 60)
    print("AISec - Phishing Detection Model Training")
    print("=" * 60)
    
    # Try to load real dataset
    dataset_path = "phiusiil_phishing_url_dataset.csv"
    
    if os.path.exists(dataset_path):
        print(f"Loading dataset from {dataset_path}...")
        df = pd.read_csv(dataset_path)
        # Adapt column names to dataset format
        url_col = next((c for c in df.columns if 'url' in c.lower()), df.columns[0])
        label_col = next((c for c in df.columns if 'label' in c.lower() or 'class' in c.lower()), df.columns[-1])
        urls = df[url_col].tolist()
        labels = (df[label_col] == 1).astype(int).tolist()
        print(f"Loaded {len(urls)} samples from dataset")
    else:
        print("Real dataset not found. Generating synthetic training data...")
        print("For production, download PhiUSIIL from Kaggle or use PhishTank CSV.")
        urls, labels = generate_sample_data(n_phishing=2000, n_benign=2000)
        print(f"Generated {len(urls)} synthetic samples")
    
    # Extract features
    print("\nExtracting features...")
    X = extract_feature_vectors(urls)
    y = np.array(labels)
    
    print(f"Feature matrix shape: {X.shape}")
    print(f"Phishing samples: {y.sum()} | Benign samples: {(y==0).sum()}")
    
    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining on {len(X_train)} samples, testing on {len(X_test)} samples")
    
    # Train model
    if HAS_XGB:
        print("\nTraining XGBoost classifier...")
        model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42,
        )
    else:
        print("\nTraining GradientBoosting classifier...")
        from sklearn.ensemble import GradientBoostingClassifier
        model = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42,
        )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    print("\n" + "=" * 40)
    print("Model Evaluation Results:")
    print("=" * 40)
    print(classification_report(y_test, y_pred, target_names=["Benign", "Phishing"]))
    print(f"AUC-ROC Score: {roc_auc_score(y_test, y_proba):.4f}")
    
    # Save model
    os.makedirs("models", exist_ok=True)
    model_path = "models/phishing_model.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    
    print(f"\n✅ Model saved to {model_path}")
    print("✅ Training complete!")
    
    # Feature importance
    if HAS_XGB:
        feature_names = [
            "url_length", "domain_length", "special_char_ratio", "digit_ratio",
            "hyphen_count", "dot_count", "has_at_symbol", "has_ip_address",
            "has_https", "subdomain_count", "suspicious_tld", "domain_entropy",
            "path_entropy", "query_param_count", "has_redirect_param",
        ]
        importance = model.feature_importances_
        print("\nTop Feature Importances:")
        for name, imp in sorted(zip(feature_names, importance), key=lambda x: -x[1])[:10]:
            print(f"  {name}: {imp:.4f}")


if __name__ == "__main__":
    train_model()
