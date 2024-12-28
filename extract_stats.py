import json
import os
import csv
from pathlib import Path

# Directory containing results relative to current script
base_dir = Path(__file__) / "benchmark" / "llm"

# Get all results directories
results_dirs = [d for d in base_dir.iterdir() if d.is_dir() and d.name.startswith("results-")]

# Initialize data structure
data = {}
all_columns = set()

# Read all statistics.json files
for dir_path in results_dirs:
    language = dir_path.name.replace("results-", "")
    stats_file = dir_path / "web" / "statistics.json"
    
    if stats_file.exists():
        with open(stats_file) as f:
            stats = json.load(f)
            data[language] = {}
            
            # Extract all metrics for each transaction type
            for transaction, metrics in stats.items():
                for metric, value in metrics.items():
                    if isinstance(value, (int, float)):  # Only include numeric values
                        column_name = f"{transaction} - {metric}"
                        all_columns.add(column_name)
                        data[language][column_name] = value

# Write to CSV
output_file = base_dir / "benchmark_statistics.csv"
columns = sorted(list(all_columns))

with open(output_file, 'w', newline='') as f:
    writer = csv.writer(f)
    # Write header
    writer.writerow(['Language'] + columns)
    
    # Write data for each language
    for language in sorted(data.keys()):
        row = [language]
        for column in columns:
            row.append(data[language].get(column, ''))
        writer.writerow(row)

print(f"Data has been written to {output_file}")
