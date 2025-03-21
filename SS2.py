import socket
import json
import sqlite3
import hashlib
import datetime

# Server Configuration
HOST = '0.0.0.0'  # Listen on all network interfaces
PORT = 12345  # Choose an appropriate port

def compute_hash(data):
    """Compute a SHA-256 hash of the given SCADA data."""
    data_copy = data.copy()
    data_copy.pop("hash", None)  # Remove existing hash before recalculating
    data_str = json.dumps(data_copy, sort_keys=True)
    return hashlib.sha256(data_str.encode()).hexdigest()

def log_message(message):
    """Log messages for debugging."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def store_data(data):
    """Store the received SCADA data into the database, adding a timestamp and verifying hash."""
    conn = sqlite3.connect('attacker.db')
    cursor = conn.cursor()

    try:
        data = json.loads(data)  # Parse JSON data
        received_hash = data.pop("hash", None)  # Remove hash before storing
        
        # Compute hash of received data (excluding hash field itself)
        computed_hash = compute_hash(data)

        # Verify data integrity
        if received_hash != computed_hash:
            data["status"] = "tampered"
            log_message("🚨 Data integrity compromised! Marking as tampered.")
        else:
            data["status"] = "idle"
            log_message("✔ Verified: Data integrity confirmed.")

        # Check if 'timestamp' column exists in the table
        cursor.execute("PRAGMA table_info(ScadaNetwork);")
        columns_in_db = [row[1] for row in cursor.fetchall()]

        # Add timestamp only if the column exists
        if "timestamp" in columns_in_db:
            data["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Ensure 'hash' is not in data before inserting
        if "hash" in data:
            del data["hash"]

        # Log final data being inserted
        log_message(f"📝 Final Data for DB Insert: {json.dumps(data, indent=2)}")

        # Prepare SQL query (excluding hash)
        columns = ', '.join(f'"{col}"' for col in data.keys())
        placeholders = ', '.join(['?'] * len(data))
        values = tuple(data.values())

        sql = f"INSERT INTO ScadaNetwork ({columns}) VALUES ({placeholders})"
        cursor.execute(sql, values)
        conn.commit()
        
        log_message("✅ Data stored successfully.")

    except Exception as e:
        log_message(f"❌ Error storing data: {e}")

    finally:
        conn.close()

def start_server():
    """Start the SCADA server to receive and store data."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)

    log_message(f"🚀 Server started on {HOST}:{PORT}")

    while True:
        client_socket, client_address = server.accept()
        log_message(f"🔌 Connection from {client_address}")

        try:
            data = client_socket.recv(1024).decode('utf-8')
            if data:
                log_message(f"📩 Received data: {data}")
                store_data(data)  # Store data in database
        except Exception as e:
            log_message(f"⚠️ Error receiving data: {e}")

        client_socket.close()

if __name__ == "__main__":
    start_server()
