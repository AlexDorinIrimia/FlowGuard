import time
from backend.packet_capture.Flow import Flow

class FlowManager:
    def __init__(self, timeout=30):
        self.flows = {}  # key -> Flow instance
        self.timeout = timeout  # flow timeout in seconds

    def _generate_flow_key(self, packet):
        if 'IP' not in packet:
            return None
        proto = packet['IP'].proto
        src = (packet['IP'].src, packet['IP'].sport if 'TCP' in packet or 'UDP' in packet else 0)
        dst = (packet['IP'].dst, packet['IP'].dport if 'TCP' in packet or 'UDP' in packet else 0)
        key = tuple(sorted([src, dst])) + (proto,)
        return key

    def add_packet(self, packet):
        key = self._generate_flow_key(packet)
        if key is None:
            return

        if key not in self.flows:
            self.flows[key] = Flow(key)

        self.flows[key].add_packet(packet)

    def extract_expired_flows(self):
        now = time.time()
        expired = []

        for key in list(self.flows.keys()):
            flow = self.flows[key]
            if flow.is_inactive(self.timeout):
                # Only expire if it had more than 1 packet or aged past a grace period
                if flow.packet_count > 1 or (now - flow.first_seen > self.timeout + 5):
                    expired.append((key, self.flows.pop(key)))

        return expired

    def force_expire_all(self):
        """Use at the end of a capture to flush all flows."""
        expired = list(self.flows.items())
        self.flows.clear()
        return expired
