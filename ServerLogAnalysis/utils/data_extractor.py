import pandas as pd
import re
import os
import sys

# Append parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from utils import SetEnv

def main():
    # Set the current directory
    parent_dir = SetEnv.set_path()

    # Specify the path to the log file relative to the parent directory
    log_file_path = os.path.join(parent_dir, 'data/raw/server_logs.txt')

    # Read the log file
    with open(log_file_path, 'r') as file:
        logs = file.readlines()

    # Initialize lists to store parsed data
    ip_addresses = []
    timestamps = []
    request_methods = []
    request_paths = []
    status_codes = []
    user_agents = []

    # Regular expression pattern to match the log format
    pattern = r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>.*?)\] "(?P<method>.*?) (?P<path>.*?) .*?" (?P<status>\d+) .*?"(' \
            r'?P<user_agent>.*?)" '

    # Iterate over each log entry and extract information
    for log in logs:
        match = re.match(pattern, log)
        if match:
            ip_addresses.append(match.group('ip'))
            timestamps.append(match.group('timestamp'))
            request_methods.append(match.group('method'))
            request_paths.append(match.group('path'))
            status_codes.append(match.group('status'))
            user_agents.append(match.group('user_agent'))

    # Create a DataFrame
    data = {
        'IP Address': ip_addresses,
        'Timestamp': timestamps,
        'Request Method': request_methods,
        'Request Path': request_paths,
        'Status Code': status_codes,
        'User Agent': user_agents
    }
    df = pd.DataFrame(data)

    # Specify the path to save the CSV file relative to the parent directory
    data_dir = os.path.join(parent_dir, 'data/csv')
    csv_file = os.path.join(data_dir, 'server_logs.csv')

    # Save the DataFrame to a CSV file
    df.to_csv(csv_file, index=False)

    # Display the CSV file contents
    with open(csv_file,  'r') as file:
        csv_contents = file.read()

    print(csv_contents)


# Run the data extraction if this file is executed as a script
if __name__ == '__main__':
    main()