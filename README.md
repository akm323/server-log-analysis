# Server-log-analysis
Server log management is a critical task for organizations relying on web services, but it often presents challenges such as processing large volumes of data, identifying performance bottlenecks, and detecting security threats. Traditional approaches may be inefficient, lacking real-time updates or actionable insights. The proposed system addresses these issues by providing a real-time, web based solution for analyzing and visualizing server log data. Built using Flask, SQLAlchemy, 
Pandas, and Plotly, the system streamlines log analysis through intuitive dashboards and advanced visualizations. It identifies key metrics such as frequent IPs, request patterns, status code distributions, and device, allowing administrators to monitor server activity effectively. This system empowers users to quickly detect anomalies, optimize server performance, and enhance security by uncovering patterns and irregularities in the data. With user-friendly interfaces, it ensures that administrators have immediate access to critical insights, facilitating prompt and informed decision-making. By resolving the inefficiencies of traditional log 
management, the system is an essential tool for improving server reliability and operational efficiency. The system employs quantitative methodologies to derive insights from numeric and structured log data, presenting the results through intuitive visualizations and summary metrics. By combining robust data processing capabilities with interactive dashboards, this system is a comprehensive tool for server management and performance analysis, streamlining troubleshooting and decision-making processes.
# How to run the system
Make sure to create the .env file and give a value to the SECRET_KEY in it. Then run the main.py and go to website link, now you have the system running.
=======
# Server Log Analysis System

A comprehensive real-time web application for analyzing and visualizing server log data. This system provides administrators with powerful tools to monitor server performance, detect anomalies, and gain insights into user behavior patterns.

## 🚀 Features

### Real-time Log Processing
- **Live Data Extraction**: Automatically processes new log entries from raw log files
- **Real-time Updates**: WebSocket-based live updates to dashboards
- **File Monitoring**: Watches log files for changes and processes them automatically

### Interactive Dashboards
- **Overview Dashboard**: Comprehensive metrics and visualizations
- **IP Tracking**: Detailed analysis of specific IP addresses
- **URL Tracking**: Analysis of specific request paths and endpoints
- **User Management**: Admin interface for user account management

### Analytics & Visualizations
- **Traffic Analysis**: Request patterns over time, peak usage periods
- **Status Code Distribution**: HTTP response code analysis with pie charts
- **Device Analysis**: User agent parsing and device type distribution
- **Geographic Analysis**: IP geolocation mapping (optional)
- **Performance Monitoring**: Response time tracking and bottleneck identification

### Security & User Management
- **User Authentication**: Secure login system with password hashing
- **Session Management**: Flask-Login integration for secure sessions
- **Admin Controls**: User creation, deletion, and password management

## 🛠️ Technology Stack

- **Backend**: Flask (Python web framework)
- **Database**: SQLite with SQLAlchemy ORM
- **Data Processing**: Pandas for data manipulation and analysis
- **Visualization**: Plotly for interactive charts and graphs
- **Real-time**: Flask-SocketIO for live updates
- **Authentication**: Flask-Login for user management
- **File Monitoring**: Watchdog for log file changes

## 📁 Project Structure

```
server-log-analysis-main/
├── ServerLogAnalysis/
│   ├── app.py                 # Main Flask application
│   ├── main.py               # Application entry point
│   ├── config.py             # Configuration settings
│   ├── data_queries.py       # Database query functions
│   ├── Geolocation_Analysis.py # IP geolocation features
│   ├── data/
│   │   ├── raw/              # Raw log files
│   │   ├── csv/              # Processed CSV data
│   │   └── processed/        # Analysis output files
│   ├── templates/            # HTML templates
│   │   ├── index.html        # Main dashboard
│   │   ├── login.html        # Login page
│   │   ├── track_ip.html     # IP tracking page
│   │   └── track_url.html    # URL tracking page
│   └── utils/
│       ├── data_extractor.py # Log parsing and CSV conversion
│       ├── SummaryAnalysis.py # Statistical analysis
│       └── SetEnv.py         # Environment configuration
├── requirements.txt          # Python dependencies
└── README.md
```

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd server-log-analysis-main
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   Create a `.env` file in the project root:
   ```env
   SECRET_KEY=your-secret-key-here
   ```

4. **Prepare log data**
   - Place your server log files in `ServerLogAnalysis/data/raw/`
   - The system expects Apache/Nginx style log format

5. **Run the application**
   ```bash
   cd ServerLogAnalysis
   python main.py
   ```

6. **Access the dashboard**
   - Open your browser and go to `http://localhost:5000`
   - Default admin credentials: username: `ak`, password: `ak249`

## 📊 Usage

### Main Dashboard
- View real-time server metrics and visualizations
- Monitor request patterns, status codes, and device distributions
- Access summary statistics and performance indicators

### IP Tracking
- Select specific IP addresses from the dropdown
- Analyze request patterns, status codes, and device types for that IP
- View time-series data for suspicious or high-activity IPs

### URL Tracking
- Track specific request paths and endpoints
- Analyze which IPs are accessing particular resources
- Monitor performance and error rates for specific URLs

### User Management
- Create new user accounts
- Manage existing users
- Change passwords securely

## 🔧 Configuration

### Database
The system uses SQLite by default. To use PostgreSQL:
1. Update `config.py` with your database URI
2. Install `psycopg2` for PostgreSQL support

### Log Format
The system expects logs in Apache/Nginx format:
```
IP - - [timestamp] "method path protocol" status size "user-agent" "referrer"
```

### Customization
- Modify `data_extractor.py` to support different log formats
- Update visualization parameters in `app.py`
- Customize HTML templates in the `templates/` directory

## 📈 Analytics Features

### Summary Statistics
- Total requests and unique IP addresses
- Status code distribution and most common responses
- Average response times and performance metrics

### Traffic Analysis
- Hourly and daily request patterns
- Peak usage identification
- Geographic distribution (with geolocation enabled)

### Security Monitoring
- Suspicious IP detection
- Error rate monitoring
- User agent analysis for bot detection

## 🛡️ Security Features

- Password hashing with Werkzeug
- Session-based authentication
- CSRF protection
- Input validation and sanitization

## 📝 API Endpoints

- `GET /` - Main dashboard
- `GET /login` - Login page
- `POST /login` - Authentication
- `GET /track_ip` - IP tracking interface
- `POST /track_ip` - IP analysis data
- `GET /track_url` - URL tracking interface
- `POST /track_url` - URL analysis data
- `GET /manage_users` - User management
- `POST /signup` - User registration
- `POST /change_password` - Password change

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:
1. Check the project documentation
2. Review existing issues
3. Create a new issue with detailed description

## 🔄 Updates

The system automatically:
- Monitors log files for new entries
- Updates the database with new data
- Refreshes visualizations in real-time
- Maintains data integrity and consistency
