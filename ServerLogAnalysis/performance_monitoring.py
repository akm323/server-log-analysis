import os
import pandas as pd
import matplotlib.pyplot as plt
from textwrap import shorten
from utils import SetEnv

def performance_monitoring(file_dir):
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

    # Convert the Timestamp column to datetime
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%d/%b/%Y:%H:%M:%S %z')

    # Extract relevant columns
    relevant_columns = ['Timestamp', 'Request Path', 'Status Code']
    df = df[relevant_columns]

    # Filter out successful requests (status code 200)
    successful_requests = df[df['Status Code'] == 200]

    # Group by request path and calculate the number of requests
    response_times = successful_requests.groupby('Request Path').size()

    # Shorten request paths for the plot
    shortened_paths = [shorten(path, width=30, placeholder="...") for path in response_times.index]

    # Prepare the analysis results as a string
    output_string = "Response Times for Different Paths/Resources:\n"
    output_string += response_times.to_string() + "\n"

    # Print summary statistics
    print(output_string)

    # Ensure the output directory exists
    output_dir = f'{_env}/processed'
    os.makedirs(output_dir, exist_ok=True)

    # Save summary statistics to a text file
    output_path = f'{output_dir}/performance_monitoring.txt'
    with open(output_path, 'w') as file:
        file.write(output_string)

    # Plot response times for different paths or resources
    plt.figure(figsize=(12, 6))
    plt.bar(shortened_paths, response_times.values, color='skyblue')
    plt.title('Response Times for Different Paths/Resources')
    plt.xlabel('Request Path')
    plt.ylabel('Number of Requests')
    plt.xticks(rotation=45, ha='right', fontsize=8)  # Adjusted fontsize
    plt.grid(axis='y')
    plt.tight_layout()
    plt.show()

def main():
    performance_monitoring('data/csv/server_logs.csv')

if __name__ == "__main__":
    main()
