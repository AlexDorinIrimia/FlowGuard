import threading
import time
from scapy.all import *
from packet_capture.FlowManager import FlowManager
from ml_model.utils.AttackDetector import AttackDetector
from packet_capture.packet_sniffer import PacketSniffer
from alerting.Notifier import format_alert_message, send_notificaton
from backend.logging.logger import IDSLogger

class IntegratedDetectionSystem:
    def __init__(self, interface=None):
        self.packet_sniffer = PacketSniffer(interface, self.packet_handler)
        self.flow_manager = FlowManager()
        self.attack_detector = AttackDetector()
        self.logger = IDSLogger()

        # Thread control
        self.processing_thread = None
        self.is_running = False
        self.flow_lock = threading.Lock()

    def packet_handler(self, packet):
        """Callback for handling captured packets"""
        with self.flow_lock:
            self.flow_manager.add_packet(packet)

    def process_flows(self):
        """Background thread for processing flows"""
        while self.is_running:
            with self.flow_lock:
                expired_flows = self.flow_manager.expire_inactive_flows()
                for flow in expired_flows:
                    self.analyze_flow(flow)
            time.sleep(1)

    def analyze_flow(self, flow):
        """Analyze the flow for potential attacks"""
        try:
            features = flow.extract_features()
            predictions, confidence = self.attack_detector.predict([features])
            if predictions:
                # Extract flow information
                source_ip, destination_ip, _, _, protocol = flow.key
                packet_count = flow.packet_count  # Assuming this attribute exists in your Flow class
                
                # Format and send notification
                threat_type = predictions[0] if predictions[0] else "Unknown"
                confidence_value = confidence if confidence is not None else 0.0
                
                title, message = format_alert_message(
                    threat_type=threat_type,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    protocol=str(protocol),
                    packet_count=packet_count,
                    confidence=confidence_value
                )
                
                # Send notification with 10 seconds duration
                send_notificaton(title, message, duration=10)
                
        except Exception as e:
            print(f"Error analyzing flow: {str(e)}")

    def start(self):
        """Start the integrated detection system"""
        print("[+] Starting Integrated Detection System...")
        self.is_running = True

        # Start flow processing thread
        self.processing_thread = threading.Thread(target=self.process_flows)
        self.processing_thread.daemon = True
        self.processing_thread.start()

        # Start packet sniffing
        self.packet_sniffer.start_sniffing()

    def stop(self):
        """Stop the integrated detection system"""
        print("[+] Stopping Integrated Detection System...")
        self.is_running = False
        self.packet_sniffer.stop_sniffing()

        if self.processing_thread:
            self.processing_thread.join(timeout=5)


def main():
    ids = IntegratedDetectionSystem()

    try:
        ids.start()
        print("[*] System is running. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping system...")
        ids.stop()
        print("[+] System stopped successfully")


if __name__ == "__main__":
    main()