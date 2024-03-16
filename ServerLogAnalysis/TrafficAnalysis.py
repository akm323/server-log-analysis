import pandas as pd
import matplotlib.pyplot as plt
from utils import SetEnv

def plot_time_series(df):
    # Convert the Timestamp column to datetime
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%d/%b/%Y:%H:%M:%S %z')

    # Set Timestamp as the index
    df.set_index('Timestamp', inplace=True)

    # Resample the data to get the count of requests per hour
    hourly_counts = df.resample('H').size()

    # Plotting the time-series
    plt.figure(figsize=(12, 6))
    hourly_counts.plot(color='blue', marker='o')
    plt.title('Hourly Request Count Time-Series')
    plt.xlabel('Time')
    plt.ylabel('Number of Requests')
    plt.grid(True)
    plt.show()

def main():
    # Set Working path
    _env = SetEnv.set_path()
    # Read the data from the CSV file
    df = pd.read_csv(f'{_env}/data/csv/server_logs.csv')

    # Plot time-series
    plot_time_series(df)

if __name__ == "__main__":
    main()
