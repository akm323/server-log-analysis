from flask import Flask, render_template
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
from utils import SetEnv

app = Flask(__name__)

def error_analysis(file_dir):
    _env = SetEnv.set_path()
    df = pd.read_csv(f'{_env}/{file_dir}')
    status_code_counts = df['Status Code'].value_counts()

    # Plotting
    plt.figure(figsize=(10, 6))
    status_code_counts.plot(kind='bar', color='skyblue')
    plt.title('Distribution of Status Codes')
    plt.xlabel('Status Code')
    plt.ylabel('Frequency')
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y')
    plt.tight_layout()
    
    # Convert plot to PNG image
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()
    
    return plot_url

@app.route('/')
def home():
    plot_url = error_analysis('data/csv/server_logs.csv')
    return render_template('index.html', plot_url=plot_url)

if __name__ == '__main__':
    app.run(debug=True)
