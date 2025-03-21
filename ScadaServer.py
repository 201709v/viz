import socket
import threading
import json
import sqlite3
import hashlib
import datetime

LOG_FILE = "scada_log.txt"

def compute_hash(data):
    """Compute a SHA-256 hash of the given SCADA data."""
    data_copy = data.copy()
    data_copy.pop("hash", None)  # Remove existing hash before recalculating
    data_str = json.dumps(data_copy, sort_keys=True)
    return hashlib.sha256(data_str.encode()).hexdigest()

def log_message(message):
    """Log messages to a file and print them with UTF-8 encoding."""
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    log_entry = f"{timestamp} {message}"
    print(log_entry)

    with open(LOG_FILE, "a", encoding="utf-8") as f:  # Force UTF-8 encoding
        f.write(log_entry + "\n")

def store_data(data):
    """Store the received SCADA data into the database but exclude the 'hash' field."""
    conn = sqlite3.connect('attacker.db')
    cursor = conn.cursor()

    try:
        data = json.loads(data)
        if "hash" in data:
            del data["hash"]  # Remove hash before storing

        columns = ', '.join(f'"{col}"' for col in data.keys())  
        placeholders = ', '.join(['?'] * len(data))
        values = tuple(data.values())

        sql = f"INSERT INTO ScadaNetwork ({columns}) VALUES ({placeholders})"
        cursor.execute(sql, values)
        conn.commit()
        log_message("✅ Data stored successfully in SCADA server.")

    except Exception as e:
        log_message(f"❌ Error storing data: {e}")

    finally:
        conn.close()

def handle_client(client_socket):
    """Receive SCADA messages, verify integrity, display them, and store them."""
    try:
        client_address = client_socket.getpeername()
        log_message(f"🔗 Connection established with: {client_address}")

        data = client_socket.recv(1024)
        if not data:
            return

        received_data = json.loads(data.decode())
        received_hash = received_data.get("hash")

        # Compute hash of received data (excluding hash field itself)
        computed_hash = compute_hash(received_data)

        # Verify data integrity
        if received_hash != computed_hash:
            received_data["status"] = "tampered"
            log_message("🚨 Data integrity compromised! Marking as tampered.")
        else:
            received_data["status"] = "idle"
            log_message("✔ Verified: Data integrity confirmed.")

        # Pretty-print the received data
        formatted_data = json.dumps(received_data, indent=2)
        log_message(f"📊 Received SCADA Data:\n{formatted_data}")

        # Store data in database
        store_data(json.dumps(received_data))

    except Exception as e:
        log_message(f"❌ Error handling client: {e}")

    finally:
        client_socket.close()

def server():
    """Creates a server to receive SCADA messages."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(5)
    log_message("✅ SCADA Server is running and waiting for data...")

    while True:
        client_socket, _ = server_socket.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    server()
