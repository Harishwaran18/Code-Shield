import pandas as pd
import joblib
import numpy as np

# Load model
model = joblib.load("unsw_intrusion_model.pkl")

print("Model loaded successfully")

# Create multiple random samples
sample_data = pd.DataFrame(
    np.random.rand(5, len(model.feature_names_in_)),
    columns=model.feature_names_in_
)

# Predict
predictions = model.predict(sample_data)

print("\nPredictions:")
print(predictions)

for i, p in enumerate(predictions):
    if p == 0:
        print(f"Sample {i+1}: Normal traffic")
    else:
        print(f"Sample {i+1}: Attack detected")