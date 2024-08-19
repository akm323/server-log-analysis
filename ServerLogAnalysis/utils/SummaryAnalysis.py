import os
import sys
import pandas as pd

# Append parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from utils import SetEnv

def summary(file_dir):
    # Set Working path
    _env = SetEnv.set_path()
    # Read the data from the CSV file
    df = pd.read_csv(f'{_env}/{file_dir}')

    # Convert the Timestamp column to datetime
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%d/%b/%Y:%H:%M:%S %z')

    # Calculate response time based on timestamp
    df['Response Time'] = df['Timestamp'].diff().dt.total_seconds()

    # Summary statistics
    total_requests = len(df)
    unique_ips = df['IP Address'].nunique()
    status_code_counts = df['Status Code'].value_counts()
    most_common_status_code = status_code_counts.idxmax()
    average_response_time = df['Response Time'].mean()

    # Prepare the summary statistics as a string
    summary_stats = (
        f"Total Requests: {total_requests}\n"
        f"Unique IP Addresses: {unique_ips}\n"
        "Status Code Counts:\n"
        f"{status_code_counts.to_string()}\n"
        f"Most Common Status Code: {most_common_status_code}\n"
        f"Average Response Time: {average_response_time}\n"
    )

    # Print summary statistics
    print(summary_stats)

    # Save summary statistics to a text file
    output_path = 'D:/Sem 9/Final Project/server-log-analysis-main/ServerLogAnalysis/data/processed/summary_statistics.txt'
    with open(output_path, 'w') as file:
        file.write(summary_stats)

# Run the summary function
summary('data/csv/server_logs.csv')
