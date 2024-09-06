import pandas as pd
import matplotlib.pyplot as plt
from utils import SetEnv

def error_analysis(file_dir):
    # Set Working path
    _env = SetEnv.set_path()
    # Read the data from the CSV file
    df = pd.read_csv(f'{_env}/{file_dir}')

    # Count occurrences of each status code
    status_code_counts = df['Status Code'].value_counts()

    # Plot the distribution of status codes
    plt.figure(figsize=(10, 6))
    status_code_counts.plot(kind='bar', color='skyblue')
    plt.title('Distribution of Status Codes')
    plt.xlabel('Status Code')
    plt.ylabel('Frequency')
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y')
    plt.tight_layout()
    plt.show()

    # Investigate occurrences of status code 404 (Not Found)
    if 404 in status_code_counts:
        print("Occurrences of status code 404 (Not Found):", status_code_counts[404])
        # Additional analysis or logging can be performed here for 404 errors

    # Look for patterns in other error status codes (e.g., 5xx server errors)
    server_error_codes = [code for code in status_code_counts.index if str(code).startswith('5')]
    if server_error_codes:
        print("Occurrences of server error status codes (5xx):", sum(status_code_counts[code] for code in server_error_codes))
        # Additional analysis or logging can be performed here for server errors

def main():
    error_analysis('data/csv/server_logs.csv')

if __name__ == "__main__":
    main()
