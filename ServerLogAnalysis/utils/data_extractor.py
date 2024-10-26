import pandas as pd
import re
import os
import sys
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from utils import SetEnv

LAST_LINE_FILE_PATH = 'data_extractor_last_line.txt'

def get_last_extracted_line():
    """Reads the last processed line for data extraction."""
    if os.path.exists(LAST_LINE_FILE_PATH):
        with open(LAST_LINE_FILE_PATH, 'r') as file:
            return int(file.read().strip())
    return 0

def save_last_extracted_line(line_number):
    """Saves the last processed line for data extraction."""
    with open(LAST_LINE_FILE_PATH, 'w') as file:
        file.write(str(line_number))

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_file_path, csv_file):
        self.log_file_path = log_file_path
        self.csv_file = csv_file
        self.last_position = get_last_extracted_line()  # Use last line number instead of position
        self.process_initial_data()

    # Regular expression pattern to match the log format
    pattern = re.compile(r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>.*?)\] "(?P<method>.*?) (?P<path>.*?) .*?" (?P<status>\d+) .*?"(?P<user_agent>.*?)" ')

    def process_initial_data(self):
        """Initial processing of the log file to CSV."""
        if os.path.exists(self.log_file_path):
            with open(self.log_file_path, 'r') as file:
                logs = file.readlines()
                self.last_position = len(logs)  # Set last processed line number

            data = self.parse_logs(logs)
            df = pd.DataFrame(data)
            df.to_csv(self.csv_file, mode='w', index=False)  # Write initial data to the CSV

    def parse_logs(self, logs):
        """Parse log entries from raw logs."""
        ip_addresses, timestamps, request_methods, request_paths, status_codes, user_agents = [], [], [], [], [], []

        for log in logs:
            match = self.pattern.match(log)
            if match:
                ip_addresses.append(match.group('ip'))
                timestamps.append(match.group('timestamp'))
                request_methods.append(match.group('method'))
                request_paths.append(match.group('path'))
                status_codes.append(match.group('status'))
                user_agents.append(match.group('user_agent'))

        data = {
            'IP Address': ip_addresses,
            'Timestamp': timestamps,
            'Request Method': request_methods,
            'Request Path': request_paths,
            'Status Code': status_codes,
            'User Agent': user_agents
        }
        return data

    def append_new_data(self):
        """Append new log entries to the CSV."""
        with open(self.log_file_path, 'r') as file:
            new_logs = file.readlines()[self.last_position:]  # Only new lines
            self.last_position += len(new_logs)  # Update last position

        if new_logs:
            data = self.parse_logs(new_logs)
            if data['IP Address']:  # Check if there are any new valid logs
                df = pd.DataFrame(data)
                df.to_csv(self.csv_file, mode='a', header=False, index=False)  # Append new data to the CSV
                save_last_extracted_line(self.last_position)

    def on_modified(self, event):
        """Handle log file modification."""
        if event.src_path == self.log_file_path:
            self.append_new_data()

def main():
    parent_dir = SetEnv.set_path()
    log_file_path = os.path.join(parent_dir, 'data/raw/server_logs.txt')
    csv_file = os.path.join(parent_dir, 'data/csv/server_logs.csv')

    event_handler = LogFileHandler(log_file_path, csv_file)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(log_file_path), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)  # Keep the program running to monitor the log file
            event_handler.append_new_data()  # Check for changes manually
    except KeyboardInterrupt:
        observer.stop()

    observer.join()

if __name__ == '__main__':
    main()
