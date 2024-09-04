from flask import Flask, render_template
import plotly.io as pio
import plotly.express as px
import pandas as pd

app = Flask(__name__)  # Corrected line

# Load data
df = pd.read_csv('D:/Sem 9/Final Project/server-log-analysis-main/ServerLogAnalysis/data/csv/server_logs.csv')

# Count occurrences of each IP address
ip_counts = df['IP Address'].value_counts().reset_index()
ip_counts.columns = ['IP Address', 'Count']
fig1 = px.bar(ip_counts.head(10), x='IP Address', y='Count', title='Top 10 Most Frequent IP Addresses')
plot1_html = pio.to_html(fig1, full_html=False)

# Create the 'Number of Requests' column by grouping by 'Timestamp'
requests_over_time = df.groupby('Timestamp').size().reset_index(name='Number of Requests')
fig2 = px.line(requests_over_time, x='Timestamp', y='Number of Requests', title='Requests Over Time')
plot2_html = pio.to_html(fig2, full_html=False)

# Performance monitoring
df_performance = pd.read_csv('D:/Sem 9/Final Project/server-log-analysis-main/ServerLogAnalysis/data/csv/server_logs.csv')
df_performance['Timestamp'] = pd.to_datetime(df_performance['Timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
relevant_columns = ['Timestamp', 'Request Path', 'Status Code']
df_performance = df_performance[relevant_columns]
successful_requests = df_performance[df_performance['Status Code'] == 200]
request_counts = successful_requests.groupby('Request Path').size().reset_index(name='Count')
fig3 = px.bar(request_counts, x='Request Path', y='Count', title='Number of Successful Requests for Different Paths/Resources')
plot3_html = pio.to_html(fig3, full_html=False)

# Render visualizations
@app.route('/')
def index():
    return render_template('index.html', plot1=plot1_html, plot2=plot2_html, plot3=plot3_html)

if __name__ == '__main__':  # Corrected line
    app.run(debug=True)
