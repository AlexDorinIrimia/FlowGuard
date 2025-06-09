import threading
import time
import sys
import os

# Fix paths for module imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from packet_capture.FlowManager import FlowManager  # Updated version using 5-tuple keys
from ml_model.utils.AttackDetector import AttackDetector
from packet_capture.packet_sniffer import PacketSniffer
from alerting.Notifier import format_alert_message, send_notificaton
from backend.logging.logger import IDSLogger

class IntegratedDetectionSystem:
    def __init__(self, interface=None):
        self.packet_sniffer = PacketSniffer("Wi-Fi", self.packet_handler)
        self.flow_manager = FlowManager()  #A new version already uses 5-tuple keys
        self.attack_detector = AttackDetector()
        self.logger = IDSLogger()

        self.processing_thread = None
        self.is_running = False
        self.flow_lock = threading.Lock()

        self.recent_alerts = {}  # Key: flow_key, Value: timestamp
        self.alert_cooldown = 60

    def packet_handler(self, packet):
        """Callback for handling captured packets"""
        try:
            print(f"[+] Packet captured: {packet.summary()}")
            with self.flow_lock:
                self.flow_manager.add_packet(packet)

        except Exception as e:
            print(f"[ERROR] Packet handler exception: {e}")

    def process_flows(self):
        """Background thread for processing and analyzing expired flows"""
        while self.is_running:
            try:
                with self.flow_lock:
                    expired_flows = self.flow_manager.extract_expired_flows()

                expired_flows = [flow for key, flow in expired_flows]

                for flow in expired_flows:
                    self.analyze_flow(flow)

            except Exception as e:
                self.logger.get_logger().error(f"Error in process_flows: {str(e)}", exc_info=True)

            time.sleep(1)

    def analyze_flow(self, flow):
        """Analyze the flow for potential attacks"""
        try:
            features = flow.extract_features()
            predictions, confidence_value = self.attack_detector.predict(features)

            if any(label != 'BENIGN' for label in predictions):
                (src_ip, src_port), (dst_ip, dst_port), protocol = flow.key
                packet_count = flow.packet_count
                threat_type = predictions[0]
                now = time.time()

                flow_key = ((src_ip, src_port), (dst_ip, dst_port), protocol)
                last_alert = self.recent_alerts.get(flow_key)

                if not last_alert or (now - last_alert > self.alert_cooldown):
                    self.recent_alerts[flow_key] = now

                title, message = format_alert_message(
                    threat_type=threat_type,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol=str(protocol),
                    packet_count=packet_count,
                    confidence=confidence_value
                )

                send_notificaton(title, message, duration=10)

                self.logger.get_logger().warning(
                    f"[ALERT] Threat Detected: {threat_type} | "
                    f"Src: {src_ip}:{src_port} -> Dst: {dst_ip}:{dst_port} | "
                    f"Protocol: {protocol} | Packets: {packet_count} | "
                    f"Confidence: {confidence_value:.2f}"
                )

        except Exception as e:
            self.logger.get_logger().error(f"Error analyzing flow: {str(e)}", exc_info=True)

    def start(self):
        """Start the integrated detection system"""
        print("[+] Starting Integrated Detection System...")
        self.is_running = True

        self.processing_thread = threading.Thread(target=self.process_flows)
        self.processing_thread.daemon = True
        self.processing_thread.start()

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
