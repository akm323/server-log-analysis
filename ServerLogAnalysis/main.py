from app import app, db, populate_db, socketio, start_csv_monitoring
from utils import data_extractor
import threading
import logging
import time

# Initialize logging
logging.basicConfig(level=logging.INFO)

def run_data_extractor():
    """Run the data extractor periodically in a separate thread."""
    while True:
        try:
            data_extractor.main()  # Extracts new data into CSV
            logging.info("Data extractor added new data to CSV.")
            time.sleep(5)  # Wait 5 seconds before re-running
        except Exception as e:
            logging.error(f"Error in data extractor: {e}")
            time.sleep(10)  # Retry delay if there's an error

def run_db_updater():
    """Continuously checks and updates the database with new data from CSV."""
    while True:
        try:
            with app.app_context():
                populate_db()  # Reads CSV and updates the database
            logging.info("Database updated with new data from CSV.")
            time.sleep(5)  # Wait 5 seconds before re-checking CSV
        except Exception as e:
            logging.error(f"Error updating database from CSV: {e}")
            time.sleep(10)  # Retry delay if there's an error

def create_app():
    logging.info("Setting up the application...")

    with app.app_context():
        # Ensure the database tables are created and populated
        db.create_all()
        populate_db()  # Initial data population
        logging.info("Database initialized and populated with initial data.")

    # Start the data extractor in a new thread
    extractor_thread = threading.Thread(target=run_data_extractor, daemon=True)
    extractor_thread.start()

    # Start the CSV monitoring in a separate thread
    csv_monitoring_thread = threading.Thread(target=start_csv_monitoring, daemon=True)
    csv_monitoring_thread.start()

    # Start the database updater in a new thread
    db_updater_thread = threading.Thread(target=run_db_updater, daemon=True)
    db_updater_thread.start()

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True, use_reloader=False)
