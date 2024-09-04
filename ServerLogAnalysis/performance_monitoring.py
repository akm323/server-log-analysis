import pandas as pd
import plotly.express as px

def performance_monitoring(file_dir: str) -> None:
    """
    Analyze server logs and display a bar chart of successful requests by path.

    Args:
        file_dir (str): The directory of the server log file.
    """
    try:
        df = pd.read_csv(file_dir)
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
        relevant_columns = ['Timestamp', 'Request Path', 'Status Code']
        df = df[relevant_columns]
        successful_requests = df[df['Status Code'] == 200]
        request_counts = successful_requests.groupby('Request Path').size().reset_index(name='Count')
        fig = px.bar(request_counts, x='Request Path', y='Count', title='Number of Successful Requests for Different Paths/Resources')
        fig.show()
    except FileNotFoundError:
        print(f"Error: File not found at {file_dir}")
    except pd.errors.EmptyDataError:
        print(f"Error: File at {file_dir} is empty")
    except pd.errors.ParserError as e:
        print(f"Error: Unable to parse file at {file_dir}: {e}")

def main() -> None:
    """
    Main entry point of the script.
    """
    performance_monitoring('data/csv/server_logs.csv')

if __name__ == "_main_":
    main()