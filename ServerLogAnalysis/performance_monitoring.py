import pandas as pd
import matplotlib.pyplot as plt
from utils import SetEnv

def performance_monitoring(file_dir):
    # Set Working path
    _env = SetEnv.set_path()
    # Read the data from the CSV file
    df = pd.read_csv(f'{_env}/{file_dir}')

    # Convert the Timestamp column to datetime
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%d/%b/%Y:%H:%M:%S %z')

    # Extract relevant columns
    relevant_columns = ['Timestamp', 'Request Path', 'Status Code']
    df = df[relevant_columns]

    # Filter out successful requests (status code 200)
    successful_requests = df[df['Status Code'] == 200]

    # Group by request path and calculate average response time
    response_times = successful_requests.groupby('Request Path').size()

    # Plot response times for different paths or resources
    plt.figure(figsize=(12, 6))
    response_times.plot(kind='bar', color='skyblue')
    plt.title('Response Times for Different Paths/Resources')
    plt.xlabel('Request Path')
    plt.ylabel('Number of Requests')
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y')
    plt.tight_layout()
    plt.show()

def main():
    performance_monitoring('data/csv/server_logs.csv')

if __name__ == "__main__":
    main()
