import pandas as pd
import numpy as np

print("=" * 60)
print("🌐 GENERATING IoT NETWORK TRAFFIC DATASET")
print("=" * 60)

np.random.seed(42)
n_samples = 8000

print("\n📊 Creating network traffic features...")

# Create realistic IoT network traffic features
data = {
    'Flow_Duration': np.random.exponential(2000, n_samples),
    'Total_Fwd_Packets': np.random.exponential(50, n_samples),
    'Total_Bwd_Packets': np.random.exponential(40, n_samples),
    'Total_Len_Fwd_Packets': np.random.exponential(5000, n_samples),
    'Total_Len_Bwd_Packets': np.random.exponential(4000, n_samples),
    'Fwd_Packet_Len_Max': np.random.randint(0, 1500, n_samples),
    'Fwd_Packet_Len_Min': np.random.randint(0, 100, n_samples),
    'Bwd_Packet_Len_Max': np.random.randint(0, 1500, n_samples),
    'Bwd_Packet_Len_Min': np.random.randint(0, 100, n_samples),
    'Flow_IAT_Mean': np.random.exponential(500, n_samples),
    'Flow_IAT_Std': np.random.exponential(1000, n_samples),
    'Fwd_IAT_Mean': np.random.exponential(300, n_samples),
    'Bwd_IAT_Mean': np.random.exponential(400, n_samples),
    'Dst_Port': np.random.randint(1, 65535, n_samples),
    'Protocol_Type': np.random.choice([6, 17, 1], n_samples),
}

df = pd.DataFrame(data)

print("🔄 Creating labels (Normal vs Botnet)...")

# Create labels: 75% Normal, 25% Botnet
labels = np.random.choice(['Normal', 'Botnet'], n_samples, p=[0.75, 0.25])

# Add realistic botnet patterns
botnet_indices = np.where(labels == 'Botnet')[0]
df.loc[botnet_indices, 'Total_Fwd_Packets'] *= 3
df.loc[botnet_indices, 'Flow_Duration'] *= 0.3
df.loc[botnet_indices, 'Fwd_IAT_Mean'] *= 0.5
df.loc[botnet_indices, 'Total_Len_Fwd_Packets'] *= 2
df.loc[botnet_indices, 'Dst_Port'] = np.random.choice([53, 80, 443, 8080], len(botnet_indices))

df['Label'] = labels

print("💾 Saving dataset...")

# Save to CSV
df.to_csv('data/iot_dataset.csv', index=False)

print("\n" + "=" * 60)
print("✅ DATASET GENERATED SUCCESSFULLY!")
print("=" * 60)
print(f"📊 Total Samples: {n_samples:,}")
print(f"✅ Normal Traffic: {sum(labels == 'Normal'):,} ({sum(labels == 'Normal')/n_samples*100:.1f}%)")
print(f"❌ Botnet Traffic: {sum(labels == 'Botnet'):,} ({sum(labels == 'Botnet')/n_samples*100:.1f}%)")
print(f"🎯 Features: {df.shape[1] - 1}")
print(f"💾 Location: data/iot_dataset.csv")
print("=" * 60)
print("\n✨ Next step: python train_model.py")
print("=" * 60)