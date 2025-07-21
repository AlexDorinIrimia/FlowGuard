from scapy.layers import IP, TCP, UDP
from backend.packet_capture.Flow import Flow

class FlowManager:
    def __init__(self, timeout=30, max_lifetime=300, min_packets=5, min_duration=2.0):
        self.flows = {}
        self.timeout = timeout
        self.max_lifetime = max_lifetime
        self.min_packets = min_packets
        self.min_duration = min_duration

    def _generate_flow_key(self, packet):
        if IP not in packet:
            return None
        ip_layer = packet[IP]
        proto = ip_layer.proto

        # TCP sau UDP -> extragem porturile
        if TCP in packet:
            sport, dport = packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            sport, dport = packet[UDP].sport, packet[UDP].dport
        else:
            sport, dport = 0, 0  # fallback pentru ICMP etc.

        key = (ip_layer.src, sport, ip_layer.dst, dport, proto)
        return key

    def add_packet(self, packet):
        key = self._generate_flow_key(packet)
        if key is None:
            return

        if key not in self.flows:
            self.flows[key] = Flow(key)

        self.flows[key].add_packet(packet)

    def extract_expired_flows(self):
        expired = []
        for key in list(self.flows.keys()):
            flow = self.flows[key]
            if flow.is_expired(self.timeout, self.max_lifetime):
                if flow.packet_count >= self.min_packets or flow.get_duration() >= self.min_duration:
                    expired.append((key, self.flows.pop(key)))
                else:
                    self.flows.pop(key)  # Drop short/irrelevant flows
        return expired

    def force_expire_all(self):
        expired = []
        for key, flow in self.flows.items():
            if flow.packet_count >= self.min_packets or flow.get_duration() >= self.min_duration:
                expired.append((key, flow))
        self.flows.clear()
        return expired
