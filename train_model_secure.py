"""
Secure Model Training Script
============================
Trains the ML model and stores it with encryption.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score
import warnings
warnings.filterwarnings('ignore')

from security.config import get_security_config
from security.key_manager import KeyManager
from security.secure_storage import SecureModelStorage

print("=" * 60)
print("🔐 SECURE IoT BOTNET DETECTION - ML MODEL TRAINING")
print("=" * 60)

# Initialize security
print("\n🔒 Initializing security components...")
config = get_security_config()
key_manager = KeyManager(config)
key_manager.initialize_master_key()
secure_storage = SecureModelStorage(key_manager=key_manager)
print("✅ Security initialized!")

# Step 1: Load the dataset
print("\n📊 Step 1: Loading dataset...")
try:
    df = pd.read_csv('data/iot_dataset.csv')
    print(f"✅ Dataset loaded! Shape: {df.shape}")
except FileNotFoundError:
    print("❌ Error: iot_dataset.csv not found in data/ folder")
    exit()

# Step 2: Data cleaning
print("\n🧹 Step 2: Cleaning data...")
df = df.dropna()
print(f"✅ Dataset shape after cleaning: {df.shape}")

# Step 3: Prepare features and labels
print("\n🔧 Step 3: Preparing features...")
label_col = None
for col in ['Label', 'label', 'Class', 'class', 'attack', 'Attack']:
    if col in df.columns:
        label_col = col
        break

if label_col is None:
    print("❌ Error: Cannot find label column")
    exit()

print(f"✅ Using '{label_col}' as label column")

X = df.drop(label_col, axis=1)
y = df[label_col]

# Step 4: Handle categorical features
print("\n📝 Step 4: Converting categorical features...")
X = pd.get_dummies(X, drop_first=True)
print(f"✅ Features after encoding: {X.shape[1]} features")

# Step 5: Split data
print("\n✂️ Step 5: Splitting data...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"✅ Train: {X_train.shape[0]}, Test: {X_test.shape[0]}")

# Step 6: Normalize features
print("\n📈 Step 6: Normalizing features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Step 7: Train the model
print("\n🚀 Step 7: Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train_scaled, y_train)
print("✅ Model trained!")

# Step 8: Evaluate
print("\n📊 Step 8: Evaluating...")
y_pred = model.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)

print(f"✅ Accuracy:  {accuracy*100:.2f}%")
print(f"✅ Precision: {precision*100:.2f}%")
print(f"✅ Recall:    {recall*100:.2f}%")

# Step 9: Save with encryption
print("\n🔐 Step 9: Saving model with encryption...")
metadata = secure_storage.save_model(
    model=model,
    model_id='botnet_model',
    model_type='sklearn_random_forest',
    description='IoT Botnet Detection Model',
    accuracy=accuracy,
    additional_files={
        'scaler': scaler,
        'feature_columns': X.columns
    }
)

print(f"✅ Model encrypted and saved!")
print(f"   Model ID: {metadata.model_id}")
print(f"   Version: {metadata.version}")
print(f"   Key ID: {metadata.key_id}")
print(f"   Checksum: {metadata.checksum_sha256[:16]}...")

# Also save unencrypted for backward compatibility
import joblib
joblib.dump(model, 'botnet_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
joblib.dump(X.columns, 'feature_columns.pkl')
print("✅ Unencrypted backup saved (for development)")

print("\n" + "=" * 60)
print("🎉 SECURE MODEL TRAINING COMPLETE!")
print("=" * 60)
print("\n✨ Run: python app_secure.py")
print("=" * 60)
