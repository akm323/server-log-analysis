from utils import SummaryAnalysis as sa
from app import app
import data_queries

if __name__ == '__main__':
    file_path = 'data/csv/server_logs.csv'
    sa.summary(file_path)

    
app.run(debug=True)