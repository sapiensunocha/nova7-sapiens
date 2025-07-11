import psycopg2
from psycopg2 import pool
import os

# Initialize the database connection pool using environment variables
# For example, DATABASE_URL might look like:
# "postgresql://user:password@host:port/database_name"

# Get the database URL from environment variables
DATABASE_URL = os.environ.get('DATABASE_URL')

# Check if DATABASE_URL is set
if not DATABASE_URL:
    # It's crucial to ensure this variable is set in your deployment environment (e.g., Vercel)
    # and in your local .env file for development.
    raise Exception("DATABASE_URL environment variable not set. Please configure your database connection string.")

# Initialize the connection pool with parameters parsed from the URL
try:
    db_pool = psycopg2.pool.SimpleConnectionPool(
        minconn=1, # Minimum connections
        maxconn=20, # Maximum connections
        dsn=DATABASE_URL # Data Source Name (connection string)
    )
    print("Database connection pool initialized successfully.")
except Exception as e:
    print(f"Error initializing database connection pool: {e}")
    # Re-raise the exception to prevent the application from starting without a working database connection
    raise

def get_db_connection():
    """
    Retrieves a connection from the database pool.
    """
    if db_pool is None:
        raise Exception("Database pool not initialized. Check DATABASE_URL and initialization.")
    try:
        return db_pool.getconn()
    except Exception as e:
        print(f"Error getting connection from pool: {e}")
        raise

def put_db_connection(conn):
    """
    Returns a connection to the database pool.
    """
    if db_pool is None:
        raise Exception("Database pool not initialized.")
    if conn:
        try:
            db_pool.putconn(conn)
        except Exception as e:
            print(f"Error putting connection back to pool: {e}")

# This __main__ block is for local testing of db.py if run directly
if __name__ == '__main__':
    print("Attempting to get and release a database connection for testing...")
    os.environ['DATABASE_URL'] = "postgresql://your_user:your_password@localhost:5432/your_database_name" # Placeholder for local test
    conn = None
    try:
        conn = get_db_connection()
        print("Successfully got a database connection.")
        # Optional: Perform a simple query to verify connection
        # with conn.cursor() as cur:
        #     cur.execute("SELECT version();")
        #     print("Database version:", cur.fetchone())
    except Exception as e:
        print(f"Failed to get database connection: {e}")
    finally:
        if conn:
            put_db_connection(conn)
            print("Connection released.")