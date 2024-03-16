import pandas as pd
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

    # Print summary statistics
    print(f"Total Requests: {total_requests}")
    print(f"Unique IP Addresses: {unique_ips}")
    print("Status Code Counts:")
    print(status_code_counts)
    print(f"Most Common Status Code: {most_common_status_code}")
    print(f"Average Response Time: {average_response_time}")


summary('data/csv/server_logs.csv')
