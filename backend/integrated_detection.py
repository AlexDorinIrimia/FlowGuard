from datetime import datetime
import threading
import time
from backend.ui_bridge import traffic_log
import sys
import os
from DataBase.DataBase import Database
sys.path.append(os.path.abspath('.'))
from packet_capture.FlowManager import FlowManager
from ml_model.utils.AttackDetector import AttackDetector
from packet_capture.packet_sniffer import PacketSniffer
from alerting.Notifier import AlertManager
from backend.logging.logger import IDSLogger
from backend.DataBase.DBAgent import AgentManager


class IntegratedDetectionSystem:
    def __init__(self, interface=None):
        self.packet_sniffer = PacketSniffer(packet_callback=self.packet_handler,interface=interface)
        self.flow_manager = FlowManager()
        self.attack_detector = AttackDetector()
        self.database = Database()
        self.alert_manager = AlertManager(alert_interval=300, severity_threshold="medium")
        self.db_manager = AgentManager()
        self.agent_id = self.db_manager.register_agent()
        self.logger = IDSLogger(agent_id=self.agent_id)

        self.processing_thread = None
        self.is_running: bool = False
        self.flow_lock = threading.Lock()

        # Dictionary to track recent alerts: {(src_ip, dst_ip, proto): last_alert_time}
        self.recent_alerts = {}
        self.alert_cooldown = 60
        self.alert_lock = threading.Lock()

        self._pkt_lock = threading.Lock()
        self._pkt_count = 0
        self._traffic_thr = threading.Thread(
            target=self._traffic_flusher, daemon=True
        )

    def packet_handler(self, packet):
        """Callback for handling captured packets"""
        try:
            with self.flow_lock:
                self.flow_manager.add_packet(packet)
                self._pkt_count += 1
        except Exception as e:
            print(f"[ERROR] Packet handler exception: {e}")

    def process_flows(self):
        while self.is_running:
            try:
                # Copy expired flows under lock
                with self.flow_lock:
                    expired_flows,_ = list(self.flow_manager.extract_expired_flows())

                # Process them outside lock
                for flow in expired_flows:
                    self.analyze_flow(flow)

            except Exception as e:
                print(f"Error in process_flows: {str(e)}")

            time.sleep(1)

    def analyze_flow(self, flow):
        try:
            predictions, confidence_value = self.attack_detector.predict(flow)

            if any(label != 'BENIGN' for label in predictions):
                src_ip = flow.initiator_ip
                dst_ip = flow.responder_ip
                protocol = flow.key[-1]
                packet_count = flow.packet_count
                threat_type = predictions[0]
                now = time.time()
                flow_key = (src_ip, dst_ip, protocol)
                last_alert_time = self.recent_alerts.get(flow_key)

                self.logger.log(
                    level=threat_type,
                    message=f"Alert detected: {threat_type}, packets: {packet_count}, confidence: {confidence_value}",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    confidence=confidence_value
                )

                severity = "high"  # poți calcula din confidence_value sau tipul atacului

                alert_dict = {
                        "type": threat_type,
                        "severity": severity,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                    }

                # Trimite alertă prin AlertManager
                self.alert_manager.process_alert(alert_dict)

        except Exception as e:
            print(f"[ERROR] Error analyzing flow: {e}")

    def start(self):
        """Start the IDS"""
        if not self.is_running:
            self.is_running = True
            self.processing_thread = threading.Thread(target=self.process_flows, daemon=True)
            self.processing_thread.start()
            self._traffic_thr.start()
            self.packet_sniffer.start_sniffing()

    def stop(self):
        """Stop the IDS"""
        if self.is_running:
            print("[!] Stopping IDS...")
            self.is_running = False
            if self.processing_thread:
                self.processing_thread.join(timeout=5)
            self.packet_sniffer.stop_sniffing()
            print("[+] IDS stopped successfully")

    def _traffic_flusher(self):
        """Every 5 s move count → traffic_log."""
        while self.is_running:
            time.sleep(5)
            with self._pkt_lock:
                cnt, self._pkt_count = self._pkt_count, 0
            traffic_log.append({
                "timestamp": datetime.now(),
                "packet_count": cnt
            })
