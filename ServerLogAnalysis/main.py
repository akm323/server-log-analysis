from app import app, db, populate_db, socketio, start_csv_monitoring
from utils import data_extractor
import threading
import logging
import time

# Initialize logging
logging.basicConfig(level=logging.INFO)

def run_data_extractor():
    """Run the data extractor in a separate thread."""
    try:
        data_extractor.main()
        logging.info("Data extractor started successfully.")
        time.sleep(5)  # Wait 5 seconds before re-running
    except Exception as e:
        logging.error(f"Error in data extractor: {e}")
        time.sleep(10)  # Wait before retrying if there's an error

def create_app():
    logging.info("Setting up the application...")

    with app.app_context():
        # Ensure the database tables are created and populated
        db.create_all()
        populate_db()
        logging.info("Database initialized and populated with initial data.")

    # Start the data extractor in a new thread
    extractor_thread = threading.Thread(target=run_data_extractor, daemon=True)
    extractor_thread.start()

    # Start the CSV monitoring in a separate thread
    csv_monitoring_thread = threading.Thread(target=start_csv_monitoring, daemon=True)
    csv_monitoring_thread.start()

    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True, use_reloader=False)
