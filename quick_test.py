import requests
import time

print("Testing backend...")
time.sleep(1)

try:
    response = requests.get("http://127.0.0.1:8009/regions", timeout=5)
    print(f"Response: {response.status_code}")
    print(f"Data: {response.text[:200]}")
except Exception as e:
    print(f"Error: {e}")
