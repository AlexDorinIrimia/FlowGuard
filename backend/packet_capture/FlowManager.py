import time
from scapy.layers.inet import IP, TCP, UDP
from enum import Enum
from .Flow import Flow

class PacketDirection(Enum):
    FORWARD = 1
    REVERSE = 2

class FlowManager:
    def __init__(self, inactivity_timeout=15, max_lifetime=180):
        self.flows = {}
        self.inactivity_timeout = inactivity_timeout
        self.max_lifetime = max_lifetime

    def get_packet_flow_key(self, packet):
        """Return a normalized flow key for matching packets."""
        if packet is None or IP not in packet:
            return None

        ip = packet[IP]
        proto = ip.proto
        sport = dport = 0
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        key1 = (ip.src, sport, ip.dst, dport, proto)
        key2 = (ip.dst, dport, ip.src, sport, proto)

        # Normalizare: aceeași cheie pentru pachete forward și reverse
        return min(key1, key2)

    def add_packet(self, packet):
        """Adaugă un pachet într-un flow existent sau creează unul nou."""
        if packet is None or IP not in packet:
            return

        now = getattr(packet, "time", time.time())
        key = self.get_packet_flow_key(packet)
        if key is None:
            return

        # Folosim hash-ul pentru index în dictionar, dar păstrăm tuple în Flow
        flow_hash = hash(key)
        count = 0
        while True:
            flow = self.flows.get((flow_hash, count))
            if flow is None:
                flow = Flow(key)  # Flow păstrează tuple-ul original
                self.flows[(flow_hash, count)] = flow
                break

            if flow.last_seen is None:
                break

            inactive = (now - flow.last_seen) > self.inactivity_timeout
            max_life = (now - flow.first_seen) > self.max_lifetime
            finished = flow.finished

            if inactive or max_life or finished:
                count += 1
                continue
            break

        # Adaugă pachetul în flow
        flow.add_packet(packet)

    def extract_expired_flows(self, current_time=None):
        """Returnează listele de flow-uri expirate și retransmisii, ștergându-le din manager."""
        expired = []
        retrans_only = []
        now = current_time or time.time()
        to_delete = []

        for k, flow in self.flows.items():
            if flow.last_seen is None:
                to_delete.append(k)
                continue

            inactive = (now - flow.last_seen) > self.inactivity_timeout
            max_life = (now - flow.first_seen) > self.max_lifetime
            finished = flow.finished

            if inactive or max_life or finished:
                if getattr(flow, "retrans_only", False):
                    retrans_only.append(flow)
                else:
                    expired.append(flow)
                to_delete.append(k)

        for k in to_delete:
            del self.flows[k]

        return expired, retrans_only

    def force_expire_all(self):
        """Expirează toate flow-urile și returnează feature-urile lor."""
        expired_features = []
        for flow in self.flows.values():
            if flow is not None:
                expired_features.append(flow.extract_features())
        self.flows.clear()
        return expired_features
