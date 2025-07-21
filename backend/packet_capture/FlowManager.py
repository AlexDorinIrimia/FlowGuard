from backend.packet_capture.Flow import Flow

class FlowManager:
    def __init__(self, timeout=30, max_lifetime=300, min_packets=5, min_duration=2.0):
        self.flows = {}
        self.timeout = timeout
        self.max_lifetime = max_lifetime
        self.min_packets = min_packets
        self.min_duration = min_duration

    def _generate_flow_key(self, packet):
        if 'IP' not in packet:
            return None
        proto = packet['IP'].proto
        src = (packet['IP'].src, packet['IP'].sport if 'TCP' in packet or 'UDP' in packet else 0)
        dst = (packet['IP'].dst, packet['IP'].dport if 'TCP' in packet or 'UDP' in packet else 0)
        key = tuple(sorted([src, dst])) + (proto,)
        return key, packet['IP'].src

    def add_packet(self, packet):
        result = self._generate_flow_key(packet)
        if result is None:
            return
        key, initiator_ip = result

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
