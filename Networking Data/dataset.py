import os
import pandas as pd

csv_directory = "MachineLearningCVE"

if not os.path.isdir(csv_directory):
    raise FileNotFoundError(f"Directory '{csv_directory}' does not exist.")

csv_files = [f for f in os.listdir(csv_directory) if f.endswith('.csv')]
if not csv_files:
    raise FileNotFoundError(f"No CSV files found in '{csv_directory}'.")

dfs = []
for idx, csv_file in enumerate(csv_files, start=1):
    file_path = os.path.join(csv_directory, csv_file)
    print(f"[INFO] Loading file {idx}/{len(csv_files)}: {csv_file}")
    try:
        df = pd.read_csv(file_path)
        dfs.append(df)
    except Exception as e:
        print(f"[WARNING] Failed to read {csv_file}: {e}")

combined_df = pd.concat(dfs, ignore_index=True)

output_path = "combined_dataset.csv"
combined_df.to_csv(output_path, index=False)
print(f"[INFO] Combined dataset saved as '{output_path}'")
