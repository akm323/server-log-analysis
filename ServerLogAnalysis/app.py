from flask import Flask, render_template
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import io
import base64

app = Flask(__name__)

# Load data
df = pd.read_csv('D:/Sem 9/Final Project/server-log-analysis-main/ServerLogAnalysis/data/csv/server_logs.csv')

# Count occurrences of each IP address
ip_counts = df['IP Address'].value_counts().reset_index()
ip_counts.columns = ['IP Address', 'Count']

# Create the 'Number of Requests' column by grouping by 'Timestamp'
requests_over_time = df.groupby('Timestamp').size().reset_index(name='Number of Requests')

# Create visualizations

# Barplot for top 10 IP Addresses
fig1 = plt.figure(figsize=(10, 6))
sns.barplot(x='IP Address', y='Count', data=ip_counts.head(10))
plt.title('Top 10 Most Frequent IP Addresses')
plt.xlabel('IP Address')
plt.ylabel('Count')

# Convert fig1 to base64 string
img1 = io.BytesIO()
fig1.savefig(img1, format='png')
img1.seek(0)
plot_url1 = base64.b64encode(img1.getvalue()).decode()

# Lineplot for Requests Over Time
fig2 = plt.figure(figsize=(10, 6))
sns.lineplot(x='Timestamp', y='Number of Requests', data=requests_over_time)
plt.title('Requests Over Time')
plt.xlabel('Time')
plt.ylabel('Number of Requests')

# Convert fig2 to base64 string
img2 = io.BytesIO()
fig2.savefig(img2, format='png')
img2.seek(0)
plot_url2 = base64.b64encode(img2.getvalue()).decode()

# Render visualizations
@app.route('/')
def index():
    return render_template('index.html', plot_url1=plot_url1, plot_url2=plot_url2)

if __name__ == '__main__':
    app.run(debug=True)
