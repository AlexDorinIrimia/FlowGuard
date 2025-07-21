import numpy as np
from scapy.layers.inet import IP, TCP, UDP
import time

class Flow:
    def __init__(self, key):
        self.key = key
        self.packets = []
        self.first_seen = None
        self.last_seen = None
        self.finished = False
        self.initiator_dest_port = None

        self.data = {
            'forward': {'times': [], 'lengths': [], 'header_lengths': [], 'flags': []},
            'backward': {'times': [], 'lengths': [], 'header_lengths': [], 'flags': []}
        }

    def is_expired(self, inactivity_timeout, max_lifetime):
        now = time.time()
        inactive = (now - self.last_seen) > inactivity_timeout
        over_lifetime = (now - self.first_seen) > max_lifetime
        return inactive or over_lifetime

    def add_packet(self, packet):
        if IP not in packet:
            return
        now = packet.time
        direction = self.get_direction(packet)
        self.packets.append(packet)

        if self.first_seen is None:
            self.first_seen = now
        self.last_seen = now

        pkt_len = len(packet)
        header_len = len(packet[IP])
        flags = packet[TCP].flags if TCP in packet else 0

        if flags & 0x01 or flags & 0x04:  # FIN or RST
            self.finished = True

        if self.initiator_dest_port is None and direction == 'forward':
            if TCP in packet or UDP in packet:
                self.initiator_dest_port = packet.dport

        self.data[direction]['times'].append(now)
        self.data[direction]['lengths'].append(pkt_len)
        self.data[direction]['header_lengths'].append(header_len)
        self.data[direction]['flags'].append(flags)

    def get_direction(self, packet):
        return 'forward' if packet[IP].src == self.key[0] else 'backward'

    def get_duration(self):
        return self.last_seen - self.first_seen if self.first_seen and self.last_seen else 0

    def compute_stats(self, lst):
        return (max(lst), min(lst), np.mean(lst), np.std(lst)) if lst else (0, 0, 0, 0)

    def compute_packet_rate(self, count):
        duration = self.get_duration()
        return count / duration if duration > 0 else 0

    def compute_iat_mean(self, times):
        return np.mean(np.diff(times)) if len(times) > 1 else 0

    def count_flag(self, direction, flag_mask):
        return sum(bool(flag & flag_mask) for flag in self.data[direction]['flags'])

    def extract_features(self):
        fwd = self.data['forward']
        bwd = self.data['backward']
        duration = self.get_duration()

        pkt_lengths = fwd['lengths'] + bwd['lengths']
        max_pkt_len = max(pkt_lengths) if pkt_lengths else 0
        pkt_len_std = np.std(pkt_lengths) if pkt_lengths else 0
        avg_pkt_size = np.mean(pkt_lengths) if pkt_lengths else 0

        total_len_fwd = sum(fwd['lengths'])
        total_len_bwd = sum(bwd['lengths'])
        fwd_pkt_mean = np.mean(fwd['lengths']) if fwd['lengths'] else 0
        fwd_pkt_max = max(fwd['lengths']) if fwd['lengths'] else 0
        bwd_pkt_mean = np.mean(bwd['lengths']) if bwd['lengths'] else 0
        bwd_pkt_min = min(bwd['lengths']) if bwd['lengths'] else 0
        bwd_pkt_std = np.std(bwd['lengths']) if bwd['lengths'] else 0

        bwd_seg_avg = np.mean(bwd['lengths']) if bwd['lengths'] else 0
        fwd_seg_avg = np.mean(fwd['lengths']) if fwd['lengths'] else 0
        bwd_hdr_len = sum(bwd['header_lengths'])
        fwd_hdr_len = sum(fwd['header_lengths'])

        subflow_bwd_pkts = len(bwd['lengths'])
        subflow_bwd_bytes = total_len_bwd
        flow_bps = (total_len_fwd + total_len_bwd) / duration if duration > 0 else 0
        flow_iat_mean = self.compute_iat_mean(fwd['times'] + bwd['times'])

        fin_flag_cnt = self.count_flag('forward', 0x01) + self.count_flag('backward', 0x01)
        urg_flag_cnt = self.count_flag('forward', 0x20) + self.count_flag('backward', 0x20)

        return [
            avg_pkt_size,
            bwd_seg_avg,
            bwd_pkt_std,
            bwd_hdr_len,
            max_pkt_len,
            bwd_pkt_mean,
            fwd_pkt_max,
            total_len_fwd,
            subflow_bwd_pkts,
            bwd_pkt_min,
            flow_bps,
            subflow_bwd_bytes,
            fwd_pkt_mean,
            self.initiator_dest_port or 0,
            flow_iat_mean,
            fin_flag_cnt,
            fwd_hdr_len,
            np.std(fwd['lengths']) if fwd['lengths'] else 0,
            pkt_len_std,
            urg_flag_cnt,
        ]

    @property
    def packet_count(self):
        return len(self.packets)
