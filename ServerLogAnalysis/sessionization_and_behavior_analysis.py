import pandas as pd
from datetime import timedelta
from utils import SetEnv

def sessionization_and_behavior_analysis(file_dir, session_duration_minutes=30):
    # Set Working path
    _env = SetEnv.set_path()
    # Read the data from the CSV file
    df = pd.read_csv(f'{_env}/{file_dir}')

    # Convert the Timestamp column to datetime
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%d/%b/%Y:%H:%M:%S %z')

    # Define the session duration in minutes
    session_duration = timedelta(minutes=session_duration_minutes)

    # Sort the DataFrame by IP address and Timestamp
    df = df.sort_values(by=['IP Address', 'Timestamp'])

    # Initialize variables
    sessions = []
    current_session = []

    # Group requests into sessions based on IP address and time window
    for index, row in df.iterrows():
        if not current_session:
            current_session.append(row)
        else:
            time_diff = row['Timestamp'] - current_session[-1]['Timestamp']
            if row['IP Address'] == current_session[-1]['IP Address'] and time_diff <= session_duration:
                current_session.append(row)
            else:
                sessions.append(current_session)
                current_session = [row]
    if current_session:
        sessions.append(current_session)

    # Initialize the output string
    output_string = ""

    # Analyze user behavior within each session
    for session in sessions:
        output_string += f"Session for IP {session[0]['IP Address']}:\n"
        session_start = session[0]['Timestamp']
        session_end = session[-1]['Timestamp']
        session_duration = session_end - session_start
        output_string += f"Session duration: {session_duration}\n"
        output_string += "Page sequence:\n"
        for request in session:
            output_string += f"- {request['Request Path']}\n"
        output_string += "\n"

    # Print summary statistics
    print(output_string)

    # Save summary statistics to a text file
    output_path = 'D:/Sem 9/Final Project/server-log-analysis-main/ServerLogAnalysis/data/processed/session_behavior_analysis.txt'
    with open(output_path, 'w') as file:
        file.write(output_string)

def main():
    sessionization_and_behavior_analysis('data/csv/server_logs.csv')

if __name__ == "__main__":
    main()
