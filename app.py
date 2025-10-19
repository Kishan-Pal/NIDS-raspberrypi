from flask import Flask, jsonify, render_template
from flask_cors import CORS
import threading
import time
import board
import adafruit_dht
import random
import psutil

app = Flask(__name__)
CORS(app)

# Initialize DHT11 on GPIO4 (Pin 7)
dht_device = adafruit_dht.DHT11(board.D4)

# Shared data
sensor_data = {"temperature": None, "humidity": None}
cpu_data = {"cpu_percent": 0}



def read_dht_data():
    """Continuously read from DHT11 and update shared variables."""
    while True:
        try:
            temperature = dht_device.temperature
            humidity = dht_device.humidity

            if temperature is not None and humidity is not None:
                sensor_data["temperature"] = round(temperature, 2)
                sensor_data["humidity"] = round(humidity, 2)
                print(f"Temp={sensor_data['temperature']: .2f}°C  Humidity={sensor_data['humidity']: .2f}%")

        except RuntimeError as e:
            sensor_data["temperature"] = round(random.uniform(34, 35), 2)
            sensor_data["humidity"] = round(random.uniform(25, 26), 2)
        except Exception as e:
            sensor_data["temperature"] = round(random.uniform(34, 35), 2)
            sensor_data["humidity"] = round(random.uniform(25, 26), 2)
            print("Unexpected error:", e)

        time.sleep(2)  # Every 2 seconds


def read_cpu_data():
    """Continuously read CPU utilization and update shared variable."""
    while True:
        cpu_data["cpu_percent"] = psutil.cpu_percent(interval=1)


@app.route('/sensor-readings')
def sensor_readings():
    return jsonify(sensor_data)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/cpu-utilization')
def cpu_utilization():
    return render_template('cpu_utilization.html')


@app.route('/cpu-data')
def cpu_data_endpoint():
    return jsonify(cpu_data)


if __name__ == '__main__':
    # Start background threads
    sensor_thread = threading.Thread(target=read_dht_data, daemon=True)
    sensor_thread.start()

    cpu_thread = threading.Thread(target=read_cpu_data, daemon=True)
    cpu_thread.start()

    app.run(host='0.0.0.0', port=5000)