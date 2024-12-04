import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
import plotly.io as pio
import plotly.graph_objects as go
import plotly.express as px
from flask_sqlalchemy import SQLAlchemy
import pandas as pd
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
from user_agents import parse
from dotenv import load_dotenv
from flask_login import current_user
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask_socketio import SocketIO
import threading

load_dotenv()
app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = os.getenv("SECRET_KEY")  # Replace with a secure secret key
db = SQLAlchemy(app)
# Initialize Flask-SocketIO
socketio = SocketIO(app)

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if not logged in

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Define the LogEntry model
class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    request_method = db.Column(db.String(10), nullable=False)
    request_path = db.Column(db.String(2083), nullable=False)
    response_code = db.Column(db.Integer, nullable=False)
    user_agent = db.Column(db.String(255))
    referrer = db.Column(db.String(2083))

# Path to the CSV file and last processed line file
CSV_FILE_PATH = 'ServerLogAnalysis/data/csv/server_logs.csv'
LAST_LINE_FILE_PATH = 'last_line.txt'

def get_last_processed_line():
    """Reads the last processed line from a file."""
    if os.path.exists(LAST_LINE_FILE_PATH):
        with open(LAST_LINE_FILE_PATH, 'r') as file:
            return int(file.read().strip())
    return 0

def save_last_processed_line(line_number):
    """Saves the last processed line to a file."""
    with open(LAST_LINE_FILE_PATH, 'w') as file:
        file.write(str(line_number))

# Notify the front-end about new data
def notify_new_data():
    """Notify the front-end about new data in the background."""
    # Query the latest entries (customize the limit as needed)
    new_data = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(10).all()

    # Convert data to a dictionary format for JSON serialization
    new_data_list = [
        {
            "timestamp": entry.timestamp,
            "ip_address": entry.ip_address,
            "request_method": entry.request_method,
            "request_path": entry.request_path,
            "response_code": entry.response_code,
            "user_agent": entry.user_agent,
            "referrer": entry.referrer
        } for entry in new_data
    ]
    # Emit the new data to all connected clients on a 'new_data' event
    socketio.emit('new_data', new_data_list, namespace='/', broadcast=True)  # Send the event with the 'new_data' event
    app.logger.info("New data notification sent to front-end.")

def populate_db():
    """Populate the database with new data from CSV."""
    last_processed_line = get_last_processed_line()
    current_line = 0
    new_data_found = False

    df = pd.read_csv(CSV_FILE_PATH)
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%d/%b/%Y:%H:%M:%S %z')

    for index, row in df.iterrows():
        current_line = index + 1

        if current_line <= last_processed_line:
            continue

        print(f"Processing new row {current_line}: {row}")

        # Try adding entry to the database
        try:
            log_entry = LogEntry(
                timestamp=row['Timestamp'],
                ip_address=row['IP Address'],
                request_method=row['Request Method'],
                request_path=row['Request Path'],
                response_code=row['Status Code'],
                user_agent=row.get('User Agent'),
                referrer=row.get('Referrer')
            )
            db.session.add(log_entry)
            new_data_found = True
        except Exception as e:
            app.logger.error(f"Error processing row {current_line}: {e}")

    if new_data_found:
        db.session.commit()
        save_last_processed_line(current_line)
        notify_new_data()
        app.logger.info(f"New data added from line {last_processed_line + 1} to {current_line}.")
    else:
        app.logger.info("No new data found to add to the database.")


# Watchdog event handler to monitor the CSV file for changes
class CSVFileHandler(FileSystemEventHandler):
    def __init__(self, csv_file_path):
        self.csv_file_path = csv_file_path

    def on_modified(self, event):
        if event.src_path == self.csv_file_path:
            app.logger.info("CSV file modified. Populating the database with new data...")
            populate_db()

def start_csv_monitoring():
    """Monitors the CSV file for changes and updates the database automatically."""
    event_handler = CSVFileHandler(CSV_FILE_PATH)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(CSV_FILE_PATH), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)  # Keep the program running to monitor changes
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Start CSV monitoring in a background thread
threading.Thread(target=start_csv_monitoring, daemon=True).start()

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/get_new_data')
def get_new_data():
    return "New data fetched!"

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user:
           # If user exists, check the password
           if user.check_password(password):
               login_user(user)
               return redirect(url_for('index'))
           else:
               # Flash message for incorrect password
               flash('Incorrect password. Please try again.', 'login_error')
        else:
           # Flash message for invalid username
           flash('Invalid username. Please check your username.', 'login_error')

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# Protected route for the dashboard
@app.route('/')
@login_required
def index():
    # Query the top 10 most frequent IP addresses
    ip_counts = db.session.query(
        LogEntry.ip_address, db.func.count(LogEntry.ip_address).label('Count')
    ).group_by(LogEntry.ip_address).order_by(db.func.count(LogEntry.ip_address).desc()).limit(10).all()
    ip_counts_df = pd.DataFrame(ip_counts, columns=['IP Address', 'Count'])
    fig1 = px.bar(ip_counts_df, x='IP Address', y='Count', title='Top 10 Most Frequent IP Addresses')
    plot_IPfrequent_html = pio.to_html(fig1, full_html=False)

    # Query the number of requests over time
    # Query data from the database
    requests_over_time = db.session.query(
        LogEntry.timestamp.label('Timestamp')
    ).all()
    # Convert the result to a DataFrame
    requests_df = pd.DataFrame(requests_over_time, columns=['Timestamp'])
    # Group by 'Timestamp' and count the number of requests
    requests_over_time_grouped = requests_df.groupby('Timestamp').size().reset_index(name='Number of Requests')
    # Create the line plot
    fig2 = px.line(requests_over_time_grouped, x='Timestamp', y='Number of Requests', title='Requests Over Time')
    plot_numbrequests_html = pio.to_html(fig2, full_html=False)

    # Performance monitoring
    df_performance = pd.read_csv('ServerLogAnalysis/data/csv/server_logs.csv')
    df_performance['Timestamp'] = pd.to_datetime(df_performance['Timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
    relevant_columns = ['Timestamp', 'Request Path', 'Status Code']
    df_performance = df_performance[relevant_columns]
    request_counts = db.session.query(
        LogEntry.request_path, db.func.count(LogEntry.request_path).label('Count')
    ).filter(LogEntry.response_code == 200).group_by(LogEntry.request_path).all()
    request_counts_df = pd.DataFrame(request_counts, columns=['Request Path', 'Count'])
    fig3 = go.Figure(
        data=[go.Bar(
            x=request_counts_df['Request Path'].apply(lambda x: x.split('/')[-2]),
            y=request_counts_df['Count'],
            marker=dict(color=request_counts_df['Count']),
            hovertext=request_counts_df['Request Path'],
            hoverinfo="text+y"
        )],
        layout=go.Layout(
            title="Number of Requests for Different Paths/Resources",
            xaxis=dict(title='Request Path'),
            yaxis=dict(title='Count')
        )
    )
    plot_performance_html = pio.to_html(fig3, full_html=False)

    # Query the status code counts from the database
    status_code_counts = db.session.query(
        LogEntry.response_code, db.func.count(LogEntry.response_code).label('Count')
    ).group_by(LogEntry.response_code).order_by(db.func.count(LogEntry.response_code).desc()).all()
    # Convert query results to a DataFrame
    status_code_df = pd.DataFrame(status_code_counts, columns=['Status Code', 'Count'])
    # Create a Plotly pie chart
    fig4 = px.pie(
        status_code_df, 
        values='Count', 
        names='Status Code', 
        title='Status Codes',
        labels={'Status Code': 'Status Code', 'Count': 'Frequency'},
    )
    # Customize the layout and add interactivity
    fig4.update_traces(
        textinfo='percent+label',  # Display percentage and status code inside the pie
        hoverinfo='label+percent+value',  # Show label, percentage, and value on hover
        marker=dict(line=dict(color='black', width=1))  # Add black borders around slices
    )
    # Update layout for readability
    fig4.update_layout(
        showlegend=True,  # Show legend
        legend_title="Status Code",  # Title for the legend
    )
    # Convert Plotly figure to HTML
    plot_statuscode_html = pio.to_html(fig4, full_html=False)


    # Query the User Agent data from the database
    user_agents = db.session.query(
        LogEntry.user_agent  # Assuming the 'user_agent' field is in the LogEntry model
    ).all()
    # Convert the query result into a list of user agent strings
    user_agents_list = [ua[0] for ua in user_agents if ua[0]]  # Extract the user agent from the query result tuple
    # Parse each user agent string and extract device and browser information
    parsed_user_agents = [parse(ua) for ua in user_agents_list]
    devices = [ua.device.family for ua in parsed_user_agents]
    # Count the occurrences of each device and browser
    device_counts = pd.Series(devices).value_counts()
    # Convert counts to DataFrames for Plotly plotting
    device_counts_df = pd.DataFrame(device_counts.reset_index())
    device_counts_df.columns = ['Device', 'Count']
    # Create a Plotly bar chart for device distribution
    fig_device = px.bar(device_counts_df, x='Device', y='Count', title='Distribution of Devices')
    plot_device_html = pio.to_html(fig_device, full_html=False)

    # Query the log entries and count the number of requests per hour
    log_entries = db.session.query(LogEntry.timestamp).all()
    # Convert the result to a DataFrame
    log_entries_df = pd.DataFrame(log_entries, columns=['Timestamp'])
    # Convert the Timestamp column to datetime
    log_entries_df['Timestamp'] = pd.to_datetime(log_entries_df['Timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
    # Set Timestamp as the index
    log_entries_df.set_index('Timestamp', inplace=True)
    # Resample the data to get the count of requests per hour
    hourly_counts = log_entries_df.resample('H').size().reset_index(name='Count')
    # Create a Plotly line chart for the time series
    fig_time_series = px.line(
        hourly_counts,
        x='Timestamp',
        y='Count',
        title='Hourly Request Count Time-Series',
        labels={'Timestamp': 'Time', 'Count': 'Number of Requests'}
    )
    # Customize the appearance of the plot
    fig_time_series.update_traces(mode='lines+markers', marker=dict(color='blue'))
    fig_time_series.update_layout(
        xaxis_title='Time',
        yaxis_title='Number of Requests',
        xaxis_rangeslider_visible=True
    )
    # Convert Plotly figure to HTML
    plot_timeseries_html = pio.to_html(fig_time_series, full_html=False)

    # Fetch distinct IP addresses for the dropdown
    ip_addresses = db.session.query(LogEntry.ip_address).distinct().all()
    ip_addresses = [ip[0] for ip in ip_addresses]  # Flattening the result

    # Summary statistics
    total_requests = db.session.query(db.func.count(LogEntry.id)).scalar()
    unique_ips = db.session.query(db.func.count(db.distinct(LogEntry.ip_address))).scalar()
    status_code_counts = db.session.query(LogEntry.response_code, db.func.count(LogEntry.response_code)).group_by(LogEntry.response_code).all()
    most_common_status_code = db.session.query(LogEntry.response_code).group_by(LogEntry.response_code).order_by(db.func.count(LogEntry.response_code).desc()).first()[0]
    avg_response_time = round(df_performance['Timestamp'].diff().dt.total_seconds().mean(), 3)
    # Prepare summary dictionary
    summary = {
        'Total Requests': total_requests,
        'Unique IP Addresses': unique_ips,
        'Status Code Counts': dict(status_code_counts),
        'Most Common Status Code': most_common_status_code,
        'Average Response Time': avg_response_time
    }

    return render_template(
        'index.html', 
        plot_IPfrequent=plot_IPfrequent_html, 
        plot_numbrequests=plot_numbrequests_html, 
        plot_performance=plot_performance_html, 
        plot_statuscode=plot_statuscode_html, 
        plot_device=plot_device_html,
        plot_timeseries=plot_timeseries_html,
        ip_addresses=ip_addresses, 
        summary=summary
    )

@app.route('/track_ip', methods=['GET', 'POST'])
@login_required
def track_ip():
    if request.method == 'POST':
        data = request.get_json()  # Parse the JSON data from the request
        ip_address = data.get('ip_address')
        print(f"Received IP: {ip_address}")  # Debug: Check if IP is received correctly

        # Query to get the number of requests for different paths/resources filtered by IP
        request_counts = db.session.query(
            LogEntry.request_path, db.func.count(LogEntry.request_path).label('Count')
        ).filter_by(ip_address=ip_address).group_by(LogEntry.request_path).all()

        if not request_counts:
            return jsonify({"error": "No data found for this IP address"}), 404

        # Convert to DataFrame for Plotly
        request_counts_df = pd.DataFrame(request_counts, columns=['Request Path', 'Count'])

        # Create Plotly figure for the number of requests per path
        fig_requests = go.Figure(
            data=[go.Bar(
                x=request_counts_df['Request Path'].apply(lambda x: x.split('/')[-2]),  # Extract last part of path
                y=request_counts_df['Count'],
                marker=dict(color=request_counts_df['Count']),
                hovertext=request_counts_df['Request Path'],
                hoverinfo="text+y"
            )],
            layout=go.Layout(
                title=f'Number of Requests for Different Paths/Resources',
                xaxis=dict(title='Request Path'),
                yaxis=dict(title='Count')
            )
        )

        # Query for requests over time filtered by the selected IP
        requests_over_time = db.session.query(
            LogEntry.timestamp.label('Timestamp')
        ).filter_by(ip_address=ip_address).all()
        
        # Convert the result to a DataFrame
        requests_df = pd.DataFrame(requests_over_time, columns=['Timestamp'])

        if not requests_df.empty:
            # Group by 'Timestamp' and count the number of requests
            requests_over_time_grouped = requests_df.groupby('Timestamp').size().reset_index(name='Number of Requests')

            # Create the line plot for requests over time
            fig_time = px.line(requests_over_time_grouped, x='Timestamp', y='Number of Requests', 
                               title=f'Requests Over Time')
        else:
            # If no data, return an empty plot
            fig_time = px.line(title=f'Requests Over Time')
        
        # Query for status code counts filtered by the selected IP
        status_code_counts = db.session.query(
            LogEntry.response_code, db.func.count(LogEntry.response_code).label('Count')
        ).filter_by(ip_address=ip_address).group_by(LogEntry.response_code).order_by(db.func.count(LogEntry.response_code).desc()).all()

        # Convert query results to a DataFrame
        status_code_df = pd.DataFrame(status_code_counts, columns=['Status Code', 'Count'])

        if not status_code_df.empty:
            # Create a Plotly pie chart for the status codes
            fig_status = px.pie(
                status_code_df, 
                values='Count', 
                names='Status Code', 
                title=f'Status Codes',
                labels={'Status Code': 'Status Code', 'Count': 'Frequency'}
            )
            # Customize the layout and add interactivity
            fig_status.update_traces(
                textinfo='percent+label',  # Display percentage and status code inside the pie
                hoverinfo='label+percent+value',  # Show label, percentage, and value on hover
                marker=dict(line=dict(color='black', width=1))  # Add black borders around slices
            )
            # Update layout for readability
            fig_status.update_layout(
                showlegend=True,  # Show legend
                legend_title="Status Code",  # Title for the legend
            )
        else:
            # If no data, return an empty pie chart
            fig_status = px.pie(title=f'Status Codes')

        user_agents = db.session.query(
            LogEntry.user_agent
        ).filter_by(ip_address=ip_address).all()

        # Convert the query result into a list of user agent strings
        user_agents_list = [ua[0] for ua in user_agents if ua[0]]

        # Parse each user agent string and extract device information
        parsed_user_agents = [parse(ua) for ua in user_agents_list]
        devices = [ua.device.family for ua in parsed_user_agents]

        # Count the occurrences of each device
        device_counts = pd.Series(devices).value_counts()

        # Convert counts to DataFrame for Plotly plotting
        device_counts_df = pd.DataFrame(device_counts.reset_index())
        device_counts_df.columns = ['Device', 'Count']

        # Create a Plotly bar chart for device distribution
        fig_device = px.bar(device_counts_df, x='Device', y='Count', title=f'Device Distribution')



        # Convert Plotly figures to JSON
        graph_requests_json = pio.to_json(fig_requests)
        graph_time_json = pio.to_json(fig_time)
        graph_status_json = pio.to_json(fig_status)
        graph_device_json = pio.to_json(fig_device)


        # Return all three graphs (requests per path, requests over time, and status codes)
        return jsonify({
            "graph_requests": graph_requests_json,
            "graph_time": graph_time_json,
            "graph_status": graph_status_json,
            "graph_device": graph_device_json
        })

    # Handle GET requests (for the initial page)
    ip_addresses = db.session.query(LogEntry.ip_address).distinct().all()
    ip_addresses = [ip[0] for ip in ip_addresses]
    return render_template('track_ip.html', ip_addresses=ip_addresses)

def user_exists(username):
    # Replace this with the actual logic to check if the user exists in the database
    return username == "existingUser"

@app.route('/track_url', methods=['GET', 'POST'])
@login_required
def track_url():
    if request.method == 'POST':
        data = request.get_json()  # Parse the JSON data from the request
        request_path = data.get('request_path')  # Get the selected URL
        print(f"Received URL: {request_path}")  # Debug: Check if URL is received correctly

        # Query to get the number of requests for different IP addresses filtered by the selected URL
        request_counts = db.session.query(
            LogEntry.ip_address, db.func.count(LogEntry.ip_address).label('Count')
        ).filter(LogEntry.request_path.like(f"{request_path}%")).group_by(LogEntry.ip_address).all()

        if not request_counts:
            return jsonify({"error": "No data found for this URL: {request_path}"}), 404

        # Convert to DataFrame for Plotly
        request_counts_df = pd.DataFrame(request_counts, columns=['IP Address', 'Count'])

        # Create Plotly figure for the number of requests per IP address
        fig_requests = go.Figure(
            data=[go.Bar(
                x=request_counts_df['IP Address'],
                y=request_counts_df['Count'],
                marker=dict(color=request_counts_df['Count']),
                hovertext=request_counts_df['IP Address'],
                hoverinfo="text+y"
            )],
            layout=go.Layout(
                title=f'Number of Requests for Different IPs',
                xaxis=dict(title='IP Address'),
                yaxis=dict(title='Count')
            )
        )

        # Query for requests over time filtered by the selected URL
        requests_over_time = db.session.query(
            LogEntry.timestamp.label('Timestamp')
        ).filter(LogEntry.request_path.like(f"{request_path}%")).all()

        # Convert the result to a DataFrame
        requests_df = pd.DataFrame(requests_over_time, columns=['Timestamp'])

        if not requests_df.empty:
            # Group by 'Timestamp' and count the number of requests
            requests_over_time_grouped = requests_df.groupby('Timestamp').size().reset_index(name='Number of Requests')

            # Create the line plot for requests over time
            fig_time = px.line(requests_over_time_grouped, x='Timestamp', y='Number of Requests', 
                               title=f'Requests Over Time')
        else:
            # If no data, return an empty plot
            fig_time = go.Figure()
            fig_time.add_annotation(
                text="No request data available over time for this URL.",
                xref="paper", yref="paper",
                showarrow=False,
                font=dict(size=14)
            )
            fig_time.update_layout(title=f'Requests Over Time')
        
        # Query for status code counts filtered by the selected URL
        status_code_counts = db.session.query(
            LogEntry.response_code, db.func.count(LogEntry.response_code).label('Count')
        ).filter(LogEntry.request_path.like(f"{request_path}%")).group_by(LogEntry.response_code).all()

        # Convert query results to a DataFrame
        status_code_df = pd.DataFrame(status_code_counts, columns=['Status Code', 'Count'])

        if not status_code_df.empty:
            # Create a Plotly pie chart for the status codes
            fig_status = px.pie(
                status_code_df, 
                values='Count', 
                names='Status Code', 
                title=f'Status Codes',
                labels={'Status Code': 'Status Code', 'Count': 'Frequency'}
            )
            fig_status.update_traces(
                textinfo='percent+label',
                hoverinfo='label+percent+value',
                marker=dict(line=dict(color='black', width=1))
            )
            fig_status.update_layout(
                showlegend=True,
                legend_title="Status Code"
            )
        else:
            # No data case: Create an empty figure with a message
            fig_status = go.Figure()
            fig_status.add_annotation(
                text="No status code data available for this URL.",
                xref="paper", yref="paper",
                showarrow=False,
                font=dict(size=14)
            )
            fig_status.update_layout(title=f'Status Codes')
            
        # Query for user agent data filtered by the selected URL
        user_agents = db.session.query(
            LogEntry.user_agent
        ).filter(LogEntry.request_path.like(f"{request_path}%")).all()
        
        user_agents_list = [ua[0] for ua in user_agents if ua[0]]
        parsed_user_agents = [parse(ua) for ua in user_agents_list]
        devices = [ua.device.family for ua in parsed_user_agents]
        device_counts = pd.Series(devices).value_counts()

        device_counts_df = pd.DataFrame(device_counts.reset_index())
        device_counts_df.columns = ['Device', 'Count']

        # Create a Plotly bar chart for device distribution
        fig_device = px.bar(device_counts_df, x='Device', y='Count', title=f'Device Distribution')

        # Convert Plotly figures to JSON
        graph_requests_json = pio.to_json(fig_requests)
        graph_time_json = pio.to_json(fig_time)
        graph_status_json = pio.to_json(fig_status)
        graph_device_json = pio.to_json(fig_device)

        # Return all graphs (requests per IP, requests over time, status codes, and device distribution)
        return jsonify({
            "graph_requests": graph_requests_json,
            "graph_time": graph_time_json,
            "graph_status": graph_status_json,
            "graph_device": graph_device_json
        })

    # Handle GET requests (for the initial page)
    request_paths = db.session.query(LogEntry.request_path).distinct().all()
    
    # Limit URL paths to show only up to 3 folders
    def limit_url_path(url):
            if '?' in url or '#' in url:
                return url
            parts = url.split('/')
            return '/'.join(parts[:3]) if len(parts) > 3 else url

    request_paths = [limit_url_path(rp[0]) for rp in request_paths]
    
    return render_template('track_url.html', request_paths=request_paths)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Step 1: Validate the form data
        if not username or not password or not confirm_password:
            flash('Please fill out all fields', 'signup_error')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match.', 'signup_error')
            return redirect(url_for('signup'))

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'signup_error')
            return redirect(url_for('signup'))

        # Step 2: Hash the password and add the new user to the database
        try:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('manage_users'))  # Redirect to manage users page after adding a user
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'signup_error')
            return redirect(url_for('signup'))

    # Render the sign-up form if it's a GET request
    return render_template('signup.html')

@app.route('/manage_users', methods=['GET'])
@login_required
def manage_users():
    users = User.query.all()  # Fetch all users from the database
    return render_template('manage_users.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)

    # Ensure the current user cannot delete themselves
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account!', 'error')
        return redirect(url_for('manage_users'))

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'User {user_to_delete.username} has been deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'error')
    
    return redirect(url_for('manage_users'))

# Assuming you're storing the user information in a database
@app.route('/change_password', methods=['GET', 'POST'])
@login_required  # Ensures only authenticated users can access the route
def change_password():
    if request.method == 'POST':
        # Get form data
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        # Get the logged-in user from the current session
        user = current_user  # This uses Flask-Login to get the current user

        # Step 1: Verify if the old password is correct
        if not user.check_password(old_password):  # Use check_password method
            flash('Old password is incorrect', 'change_error')
            return redirect(url_for('change_password'))

        # Step 2: Check if new password and confirm password match
        if new_password != confirm_new_password:
            flash('New passwords do not match', 'change_error')
            return redirect(url_for('change_password'))

        # Step 3: Update the password in the database
        try:
            user.set_password(new_password)  # Set the new password using the method
            db.session.commit()  # Save changes to the database
            flash('Password changed successfully', 'success')
            return redirect(url_for('login'))  # Redirect to the login page after success
        except Exception as e:
            db.session.rollback()  # Rollback if there was an error during commit
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('change_password'))

    return render_template('change_password.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        start_csv_monitoring()
        # Uncomment the following line if you need to populate the database
        populate_db()
        # Create an admin user if it doesn't exist
        if User.query.filter_by(username='ak').first() is None:
            admin_user = User(username='ak')
            admin_user.set_password('ak249')  # Change the password for production use
            db.session.add(admin_user)
            db.session.commit()
    app.run(debug=True)
