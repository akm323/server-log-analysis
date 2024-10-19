#from utils import SummaryAnalysis as sa
from app import app
from utils import data_extractor
from app import app, db, populate_db

if __name__ == '__main__':
    # Call data_extractor to process the raw log file and generate the CSV
    data_extractor.main()

    #file_path = 'data/csv/server_logs.csv'
    #sa.summary(file_path)
    # Create an app context before running database operations
    with app.app_context():
        # Ensure the database tables are created
        db.create_all()

        # Now populate the database with new data from the CSV file
        populate_db()
        
    app.run(debug=True)