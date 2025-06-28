from datetime import datetime
import threading
import time
import sys
import os
from backend.ui_bridge import traffic_log
# Fix paths for module imports
import sys
import os
sys.path.append(os.path.abspath('.'))
from .packet_capture.FlowManager import FlowManager
from ml_model.utils.AttackDetector import AttackDetector
from packet_capture.packet_sniffer import PacketSniffer
from .alerting.Notifier import format_alert_message, send_notificaton
from backend.logging.logger import IDSLogger

class IntegratedDetectionSystem:
    def __init__(self, interface=None):
        self.packet_sniffer = PacketSniffer(packet_callback=self.packet_handler)
        self.flow_manager = FlowManager()  #A new version already uses 5-tuple keys
        self.attack_detector = AttackDetector()
        self.logger = IDSLogger()

        self.processing_thread = None
        self.is_running = False
        self.flow_lock = threading.Lock()

        # Dictionary to track recent alerts: {(src_ip, dst_ip): last_alert_time}
        self.recent_alerts = {}
        self.alert_cooldown = 60
        self.alert_lock = threading.Lock()

        self._pkt_lock = threading.Lock()
        self._pkt_count = 0
        self._traffic_thr = threading.Thread(
            target=self._traffic_flusher, daemon=True)

    def packet_handler(self, packet):
        """Callback for handling captured packets"""
        try:
            with self.flow_lock:
                self.flow_manager.add_packet(packet)

            with self.flow_lock:
                self._pkt_count += 1
        except Exception as e:
            print(f"[ERROR] Packet handler exception: {e}")

    def process_flows(self):
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
        try:
            features = flow.extract_features()
            predictions, confidence_value = self.attack_detector.predict(features)

            if any(label != 'BENIGN' for label in predictions):
                (src_ip, src_port), (dst_ip, dst_port), protocol = flow.key
                packet_count = flow.packet_count
                threat_type = predictions[0]
                now = time.time()

                flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)

                last_alert_time = self.recent_alerts.get(flow_key)

                if not last_alert_time or (now - last_alert_time > self.alert_cooldown):
                    # Update cooldown BEFORE sending alerts/logging
                    self.recent_alerts[flow_key] = now

                    try:
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
                    except Exception as alert_exc:
                        self.logger.get_logger().error(
                            f"Error during alerting/logging: {str(alert_exc)}", exc_info=True
                        )
                else:
                    self.logger.get_logger().debug(
                        f"Skipped alert for flow {flow_key}, cooldown active."
                    )

        except Exception as e:
            self.logger.get_logger().error(f"Error analyzing flow: {str(e)}", exc_info=True)

    def start(self):
        """Start the IDS"""
        if not self.is_running:
            self.is_running = True
            self.processing_thread = threading.Thread(target=self.process_flows)
            self.processing_thread.start()
            self._traffic_thr.start()
            self.packet_sniffer.start_sniffing()

    def stop(self):
        """Stop the IDS"""
        if self.is_running:
            print("[!] Stopping IDS...")
            self.is_running = False
            if self.processing_thread:
                self.processing_thread.join(timeout=5)  # Wait up to 5 seconds for thread to finish
            self.packet_sniffer.stop_sniffing()
            print("[+] IDS stopped successfully")

    def _traffic_flusher(self):
        """Every 5 s move count → traffic_log."""
        while self.is_running:
            time.sleep(5)
            with self._pkt_lock:
                cnt, self._pkt_count = self._pkt_count, 0
            traffic_log.append({
                "timestamp": datetime.now(),
                "packet_count": cnt
            })