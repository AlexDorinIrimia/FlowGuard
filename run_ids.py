import sys
import threading
import time
import signal
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "backend")))
from backend.integrated_detection import IntegratedDetectionSystem
from web_ui.ui_server import app, socketio

def run_web_ui():
    """Run the web UI server"""
    try:
        # Start Flask app with SocketIO
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
    except Exception as e:
        print(f"Error running web UI: {e}")
        # Don't exit here, just log the error
        print("Web UI encountered an error but will keep running")

def run_ids():
    """Run the IDS"""
    ids = IntegratedDetectionSystem()
    try:
        ids.start()
        print("[+] IDS started successfully")
        
        # Keep the IDS running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping IDS...")
        ids.stop()
        print("[+] IDS stopped successfully")
        # Re-raise the KeyboardInterrupt to stop the main thread
        raise
    except Exception as e:
        print(f"[ERROR] IDS error: {e}")
        # Don't exit here, just log the error
        print("IDS encountered an error but web UI will keep running")

def signal_handler(signum, frame):
    """Handle Ctrl+C signal"""
    print("\n[!] Received shutdown signal. Stopping system...")
    # The IDS thread will be terminated automatically since it's a daemon thread
    print("[+] System stopped successfully")
    sys.exit(0)

def main():
    try:
        # Set up the signal handler for Ctrl+C
        signal.signal(signal.SIGINT, signal_handler)
        
        print("[+] Starting Integrated Detection System with Web UI...")
        
        # Start IDS in a separate thread
        ids_thread = threading.Thread(target=run_ids, daemon=True)
        ids_thread.start()
        print("[+] IDS thread started")
        
        # Start the web UI in the main thread
        print("[+] Starting web UI...")
        run_web_ui()
        
    except KeyboardInterrupt:
        print("\n[!] Stopping system...")
        # The IDS thread will be terminated automatically since it's a daemon thread
        print("[+] System stopped successfully")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        # Don't exit here, just log the error
        print("System encountered an error but will keep running")

if __name__ == "__main__":
    main() 