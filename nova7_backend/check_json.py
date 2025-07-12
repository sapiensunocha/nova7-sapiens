import json
import os

# Define the path to your GCP key JSON file
# Make sure this path is correct relative to where you run the script,
# or provide the full absolute path as you did before.
# For simplicity, if check_json.py is in nova7_backend, and gcp-key.json is also there:
gcp_key_file_path = os.path.join(os.path.dirname(__file__), 'gcp-key.json')

# If gcp-key.json is not in the same directory as check_json.py,
# use the absolute path you provided earlier:
# gcp_key_file_path = '/Users/sapiensndatabaye/Downloads/nova7-sapiens-master/nova7_backend/gcp-key.json'

try:
    with open(gcp_key_file_path, 'r') as f:
        data = json.load(f)
    print("JSON is valid!")
    # Optionally, print some part of the data to confirm it loaded correctly
    print(f"Project ID: {data.get('project_id', 'Not found')}")
except FileNotFoundError:
    print(f"Error: File not found at '{gcp_key_file_path}'")
except json.JSONDecodeError as e:
    print(f"Error: JSON is invalid in '{gcp_key_file_path}'.")
    print(f"Details: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")