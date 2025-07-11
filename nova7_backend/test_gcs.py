import os
from dotenv import load_dotenv
from google.cloud import storage

# Load .env file (assuming it's in the project root)
# Adjust this path if your .env file is elsewhere
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
dotenv_path = os.path.join(BASE_DIR, '.env')

if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
    print(f"Loaded .env file from: {dotenv_path}")
else:
    print(f"Warning: .env file not found at {dotenv_path}. Ensure GOOGLE_APPLICATION_CREDENTIALS is set manually.")

# --- GCS Test ---
try:
    # Initialize the GCS client
    # It automatically looks for GOOGLE_APPLICATION_CREDENTIALS
    storage_client = storage.Client()
    print("Google Cloud Storage client initialized successfully.")

    # Attempt to list buckets (requires 'storage.buckets.list' permission)
    # Or, if you know your bucket name, you can try to get it directly:
    # bucket_name = os.environ.get('GCS_BUCKET_NAME', 'your-default-bucket-name-here')
    # bucket = storage_client.get_bucket(bucket_name)
    # print(f"Successfully accessed bucket: {bucket.name}")

    # Let's try listing top 5 buckets as a general test
    print("\nAttempting to list up to 5 buckets:")
    buckets = list(storage_client.list_buckets(max_results=5))
    if buckets:
        for bucket in buckets:
            print(f"- Found bucket: {bucket.name}")
        print("\nGCS connectivity test PASSED: Able to list buckets.")
    else:
        print("\nNo buckets found or listed. GCS connectivity test PASSED (client initialized, no errors).")


except Exception as e:
    print(f"\nGCS connectivity test FAILED: {e}")
    print("Please ensure:")
    print("1. Your 'gcp-key.json' file is valid and complete.")
    print("2. The 'GOOGLE_APPLICATION_CREDENTIALS' environment variable or .env entry points to the correct path of 'gcp-key.json'.")
    print("3. Your service account has sufficient permissions (at least 'Storage Admin' or 'Storage Object Admin' for full access, or 'Storage Object Viewer' for listing).")