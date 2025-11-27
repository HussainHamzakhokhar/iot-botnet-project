import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import joblib
import warnings
warnings.filterwarnings('ignore')

print("=" * 60)
print("🤖 IoT BOTNET DETECTION - ML MODEL TRAINING")
print("=" * 60)

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
print(f"Missing values before: {df.isnull().sum().sum()}")
df = df.dropna()
print(f"Missing values after: {df.isnull().sum().sum()}")
print(f"✅ Dataset shape after cleaning: {df.shape}")

# Step 3: Prepare features and labels
print("\n🔧 Step 3: Preparing features...")
# Find the label column (usually named 'Label', 'label', 'Class', or 'class')
label_col = None
for col in ['Label', 'label', 'Class', 'class', 'attack', 'Attack']:
    if col in df.columns:
        label_col = col
        break

if label_col is None:
    print("❌ Error: Cannot find label column. Available columns:", df.columns.tolist())
    exit()

print(f"✅ Using '{label_col}' as label column")

# Separate features and labels
X = df.drop(label_col, axis=1)
y = df[label_col]

print(f"Features shape: {X.shape}")
print(f"Label distribution:\n{y.value_counts()}")

# Step 4: Handle categorical features
print("\n📝 Step 4: Converting categorical features...")
X = pd.get_dummies(X, drop_first=True)
print(f"✅ Features after encoding: {X.shape[1]} features")

# Step 5: Split data
print("\n✂️ Step 5: Splitting data (80% train, 20% test)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"✅ Train set: {X_train.shape[0]} samples")
print(f"✅ Test set: {X_test.shape[0]} samples")

# Step 6: Normalize features
print("\n📈 Step 6: Normalizing features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("✅ Features normalized using StandardScaler")

# Step 7: Train the model
print("\n🚀 Step 7: Training Random Forest model...")
print("⏳ This may take 1-2 minutes...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1,
    verbose=0
)
model.fit(X_train_scaled, y_train)
print("✅ Model training complete!")

# Step 8: Make predictions
print("\n🎯 Step 8: Making predictions...")
y_pred = model.predict(X_test_scaled)
y_pred_proba = model.predict_proba(X_test_scaled)
print("✅ Predictions made!")

# Step 9: Evaluate model
print("\n📊 Step 9: Evaluating model performance...")
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)

print("\n" + "=" * 60)
print("📈 MODEL PERFORMANCE METRICS")
print("=" * 60)
print(f"✅ Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"✅ Precision: {precision:.4f} ({precision*100:.2f}%)")
print(f"✅ Recall:    {recall:.4f} ({recall*100:.2f}%)")
print("=" * 60)

# Step 10: Feature importance
print("\n🔝 Step 10: Top important features...")
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print(feature_importance.head(10).to_string(index=False))

# Step 11: Save the model
print("\n💾 Step 11: Saving model and scaler...")
joblib.dump(model, 'botnet_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
joblib.dump(X.columns, 'feature_columns.pkl')
print("✅ Model saved as 'botnet_model.pkl'")
print("✅ Scaler saved as 'scaler.pkl'")
print("✅ Features saved as 'feature_columns.pkl'")

print("\n" + "=" * 60)
print("🎉 MODEL TRAINING COMPLETE!")
print("=" * 60)
print("\n✨ Your model is ready for the dashboard!")
print("Next step: Create the Flask backend (app.py)")
print("=" * 60)