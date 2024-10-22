import os
from client import AWSAppSyncClient

username = os.getenv("USERNAME")
password = os.getenv("PASSWORD")
client = AWSAppSyncClient(username, password, True)

deviceId = client.get_devices()[0]["deviceId"]  # Get the first device

print(client.get_devices())  # Get all devices

print(
    client.get_sensors_data(  # Get the sensor data for the specified device and time range
        {
            "deviceId": deviceId,  # Get the first device
            "limit": 1000,  # Number of logs to retrieve
            "start": 1713725014,  # Start time in ms since epoch
            "end": 1713811414,  # End time in ms since epoch
        }
    )
)

print(
    client.get_current_sensors_data(deviceId)
)  # Get the current sensor data for the specified device

client.set_heating_mode(
    deviceId, "AUTO"
)  # Set the heating mode for the specified device
