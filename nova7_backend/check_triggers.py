import os
import json
import logging
from dotenv import load_dotenv
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import OperationalError, DatabaseError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
dotenv_path = os.path.join(BASE_DIR, '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
    logger.info(f"Loaded .env file from: {dotenv_path}")
else:
    logger.warning(f".env file not found at {dotenv_path}")

# Database connection details
DATABASE_URI = os.getenv('DATABASE_URL_INTERNAL', os.getenv('DATABASE_URL_INTERNAL_LOCAL', 'postgresql://neondb_owner:npg_KWJLx8l6UiEj@ep-winter-bush-a8i3nb89-pooler.eastus2.azure.neon.tech/neondb?sslmode=require'))
engine = create_engine(DATABASE_URI, pool_pre_ping=True)

# Define triggers for MarketplaceItem
def before_insert_marketplace_item_listener(mapper, connection, target):
    user = connection.execute(
        text("SELECT kyc_status FROM user WHERE id = :user_id"),
        {"user_id": target.user_id}
    ).fetchone()
    if not user or user.kyc_status != 'verified':
        raise ValueError("User must be KYC verified to list marketplace items")

from index import MarketplaceItem
event.listen(MarketplaceItem, 'before_insert', before_insert_marketplace_item_listener)

# Define triggers for WithdrawalRequest
def before_insert_withdrawal_request_listener(mapper, connection, target):
    user = connection.execute(
        text("SELECT balance, kyc_status FROM user WHERE id = :user_id"),
        {"user_id": target.user_id}
    ).fetchone()
    if not user or user.kyc_status != 'verified':
        raise ValueError("User must be KYC verified to request withdrawals")
    if user.balance < target.amount:
        raise ValueError("Insufficient balance for withdrawal")

from index import WithdrawalRequest
event.listen(WithdrawalRequest, 'before_insert', before_insert_withdrawal_request_listener)

# Define triggers for Order
def before_insert_order_listener(mapper, connection, target):
    item = connection.execute(
        text("SELECT quantity, status, price FROM marketplace_item WHERE id = :item_id"),
        {"item_id": target.item_id}
    ).fetchone()
    buyer = connection.execute(
        text("SELECT balance, kyc_status FROM user WHERE id = :buyer_id"),
        {"user_id": target.buyer_id}
    ).fetchone()
    if not item or item.status != 'active':
        raise ValueError("Item not found or not available")
    if not buyer or buyer.kyc_status != 'verified':
        raise ValueError("Buyer must be KYC verified to make purchases")
    if item.quantity is not None and target.quantity_bought > item.quantity:
        raise ValueError("Requested quantity exceeds available stock")
    total_price = item.price * target.quantity_bought
    if buyer.balance < total_price:
        raise ValueError("Insufficient balance for purchase")

from index import Order
event.listen(Order, 'before_insert', before_insert_order_listener)

def check_triggers():
    """Check and list triggers on relevant tables."""
    try:
        # Query and log triggers for relevant tables
        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT trigger_name, event_manipulation, event_object_table, action_statement
                FROM information_schema.triggers
                WHERE event_object_table IN ('team_membership', 'user', 'marketplace_item', 'withdrawal_request', 'order');
            """))
            triggers = result.fetchall()
            output = {
                "status": "success",
                "triggers": [
                    {
                        "trigger_name": trigger[0],
                        "event": trigger[1],
                        "table": trigger[2],
                        "action": trigger[3]
                    } for trigger in triggers
                ]
            }
            if triggers:
                logger.info("Triggers found on relevant tables:")
                for trigger in triggers:
                    logger.info(f"Trigger: {trigger[0]}, Event: {trigger[1]}, Table: {trigger[2]}, Action: {trigger[3]}")
            else:
                logger.info("No triggers found on relevant tables.")
                output["message"] = "No triggers found on relevant tables."
            return output
    except OperationalError as e:
        logger.error(f"Database connection error: {str(e)}")
        return {"status": "error", "message": f"Failed to connect to database: {str(e)}"}
    except DatabaseError as e:
        logger.error(f"Database query error: {str(e)}")
        return {"status": "error", "message": f"Query error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}

if __name__ == "__main__":
    result = check_triggers()
    print(json.dumps(result, indent=2))