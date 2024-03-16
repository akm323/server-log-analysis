import pandas as pd
import folium
from geopy.geocoders import Nominatim
from utils import SetEnv

def geolocation_analysis(file_dir):
    # Set Working path
    _env = SetEnv.set_path()
    # Read the data from the CSV file
    df = pd.read_csv(f'{_env}/{file_dir}')

    # Extract IP addresses
    ip_addresses = df['IP Address']

    # Initialize a geolocator
    geolocator = Nominatim(user_agent="geolocation_analysis")

    # Create a map centered at a specific location (e.g., world map)
    m = folium.Map(location=[0, 0], zoom_start=2)

    # Iterate over IP addresses to obtain coordinates and plot markers
    for ip in ip_addresses:
        try:
            location = geolocator.geocode(ip)
            if location:
                folium.Marker(location=[location.latitude, location.longitude], popup=ip).add_to(m)
        except Exception as e:
            print(f"Error geocoding IP {ip}: {e}")

    # Save the map to an HTML file
    m.save("geolocation_analysis_map.html")

def main():
    geolocation_analysis('data/csv/server_logs.csv')

if __name__ == "__main__":
    main()
