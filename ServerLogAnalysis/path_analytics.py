import os
import pandas as pd
import matplotlib.pyplot as plt
from utils import SetEnv

def path_analysis(file_dir):
    # Set Working path
    _env = SetEnv.set_path()
    
    try:
        # Read the data from the CSV file
        df = pd.read_csv(f'{_env}/{file_dir}')
    except FileNotFoundError:
        print(f"File {file_dir} not found in {_env}")
        return
    except pd.errors.ParserError:
        print("Error parsing the CSV file.")
        return

    # Extract request paths
    request_paths = df['Request Path']

    # Count the occurrences of each request path
    path_counts = request_paths.value_counts()

    # Create a DataFrame for paths and their counts
    path_df = pd.DataFrame({'Count': path_counts.values, 'Path': path_counts.index})

    # Prepare the analysis results as a string
    output_string = "Distribution of Request Paths:\n"
    output_string += path_df.to_string(index=False,) + "\n"


     # Save summary statistics to a text file
    output_path = 'D:/Sem 9/Final Project/server-log-analysis-main/ServerLogAnalysis/data/processed/path_analysis.txt'
    
    with open(output_path, 'w') as file:
        file.write(output_string)

  
    # Plot the distribution of request paths
    plt.figure(figsize=(10, 6))
    plt.bar(path_df.index, path_df['Count'], color='skyblue')
    plt.title('Distribution of Request Paths')
    plt.xlabel('Path Reference Number')
    plt.ylabel('Number of Requests')
    plt.xticks(path_df.index, path_df['Path'], rotation=90)
    plt.grid(axis='y')
    plt.tight_layout()
    plt.show()

def main():
    path_analysis('data/csv/server_logs.csv')

if __name__ == "__main__":
    main()
