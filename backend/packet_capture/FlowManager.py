from scapy.layers.inet import IP,TCP,UDP
from .Flow import Flow

class FlowManager:
    def __init__(self, timeout=10):
        self.flows = {}
        self.timeout = timeout

    def get_flow_key(self, packet):
        if IP in packet:
            proto = packet[IP].proto
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if TCP in packet or UDP in packet:
                sport = packet.sport
                dport = packet.dport
                return (src_ip, dst_ip, sport, dport, proto)
        return None

    def add_packet(self, packet):
        key = self.get_flow_key(packet)
        if not key:
            return None

        if key not in self.flows:
            self.flows[key] = Flow(key)
        self.flows[key].add_packet(packet)
        return key

    def expire_inactive_flows(self):
        expired = []
        for key in list(self.flows.keys()):
            if self.flows[key].is_inactive(self.timeout):
                expired.append(self.flows.pop(key))
        return expired

def process_flow(flow, detector):
    features = flow.extract_features()
    features_array = [features]  # Must be 2D for model
    predictions = detector.infer(features_array)
    if predictions:
        print(f"[ALERT] Attack detected: {predictions[0]} on flow {flow.key}")

def packet_callback(packet, manager, detector):
    manager.add_packet(packet)
    for flow in manager.expire_inactive_flows():
        process_flow(flow, detector)
