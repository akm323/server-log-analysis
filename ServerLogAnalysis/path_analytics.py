import pandas as pd
import matplotlib.pyplot as plt
from utils import SetEnv

def path_analysis(file_dir):
    # Set Working path
    _env = SetEnv.set_path()
    # Read the data from the CSV file
    df = pd.read_csv(f'{_env}/{file_dir}')

    # Extract request paths
    request_paths = df['Request Path']

    # Count the occurrences of each request path
    path_counts = request_paths.value_counts()

    # Create a DataFrame for paths and their counts
    path_df = pd.DataFrame({'Path': path_counts.index, 'Count': path_counts.values})

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
