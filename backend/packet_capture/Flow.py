import time
import numpy as np
from scapy.layers.inet import IP, TCP, UDP

class Flow:
    def __init__(self, key):
        self.key = key
        self.packets = []
        self.first_seen = time.time()
        self.last_seen = self.first_seen

        # Directional packet tracking
        self.data = {
            'forward': {
                'times': [],
                'lengths': [],
                'header_lengths': [],
                'flags': [],
            },
            'backward': {
                'times': [],
                'lengths': [],
                'header_lengths': [],
                'flags': [],
            }
        }

        self.finished = False
        self.initiator_dest_port = None  # Set during packet addition

    def add_packet(self, packet):
        now = time.time()
        direction = self.get_direction(packet)
        self.packets.append(packet)
        self.last_seen = now

        pkt_len = len(packet)
        header_len = len(packet[IP]) if IP in packet else 0
        flags = packet[TCP].flags if TCP in packet else 0

        # Mark flow as finished if FIN or RST
        if flags & 0x01 or flags & 0x04:
            self.finished = True

        if self.initiator_dest_port is None and direction == 'forward':
            if TCP in packet or UDP in packet:
                self.initiator_dest_port = packet.dport

        # Update relevant direction
        dir_data = self.data[direction]
        dir_data['times'].append(now)
        dir_data['lengths'].append(pkt_len)
        dir_data['header_lengths'].append(header_len)
        dir_data['flags'].append(flags)

    def get_direction(self, packet):
        src_ip = packet[IP].src
        return 'forward' if src_ip == self.key[0] else 'backward'

    def is_inactive(self, timeout):
        return (time.time() - self.last_seen) > timeout

    def is_expired(self, inactivity_timeout, max_lifetime):
        now = time.time()
        inactive = (now - self.last_seen) > inactivity_timeout
        over_lifetime = (now - self.first_seen) > max_lifetime
        return inactive or over_lifetime

    def get_duration(self):
        return self.last_seen - self.first_seen

    def compute_iat_features(self, times):
        if len(times) < 2:
            return 0, 0, 0, 0
        iats = np.diff(times)
        return np.mean(iats), np.std(iats), np.max(iats), np.min(iats)

    def compute_iat_summary(self, times):
        total = sum(np.diff(times)) if len(times) > 1 else 0
        mean, std, max_, min_ = self.compute_iat_features(times)
        return total, mean, std, max_, min_

    def compute_stats(self, lst):
        if len(lst) == 0:
            return 0, 0, 0, 0
        return max(lst), min(lst), np.mean(lst), np.std(lst)

    def compute_packet_rate(self, count):
        duration = self.get_duration()
        return count / duration if duration > 0 else 0

    def count_tcp_flags(self):
        counters = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'CWE': 0, 'ECE': 0}
        for direction in ['forward', 'backward']:
            for flags in self.data[direction]['flags']:
                counters['FIN'] += bool(flags & 0x01)
                counters['SYN'] += bool(flags & 0x02)
                counters['RST'] += bool(flags & 0x04)
                counters['PSH'] += bool(flags & 0x08)
                counters['ACK'] += bool(flags & 0x10)
                counters['URG'] += bool(flags & 0x20)
                # CWE and ECE placeholders
        return counters

    def extract_features(self):
        duration = self.get_duration()
        fwd = self.data['forward']
        bwd = self.data['backward']

        total_fwd = len(fwd['lengths'])
        total_bwd = len(bwd['lengths'])
        total_len_fwd = sum(fwd['lengths'])
        total_len_bwd = sum(bwd['lengths'])

        fwd_len_max, fwd_len_min, fwd_len_mean, fwd_len_std = self.compute_stats(fwd['lengths'])
        bwd_len_max, bwd_len_min, bwd_len_mean, bwd_len_std = self.compute_stats(bwd['lengths'])

        flow_times = sorted(fwd['times'] + bwd['times'])
        flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = self.compute_iat_features(flow_times)

        fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = self.compute_iat_summary(fwd['times'])
        bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = self.compute_iat_summary(bwd['times'])

        fwd_pck_per_s = self.compute_packet_rate(total_fwd)
        bwd_pck_per_s = self.compute_packet_rate(total_bwd)

        packet_lengths = fwd['lengths'] + bwd['lengths']
        pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std = self.compute_stats(packet_lengths)
        pkt_len_var = np.var(packet_lengths) if packet_lengths else 0

        flags = self.count_tcp_flags()

        down_up_ratio = (total_bwd / total_fwd) if total_fwd > 0 else 0
        avg_pkt_size = np.mean(packet_lengths) if packet_lengths else 0
        avg_fwd_seg_size = np.mean(fwd['lengths']) if fwd['lengths'] else 0
        avg_bwd_seg_size = np.mean(bwd['lengths']) if bwd['lengths'] else 0
        fwd_header_len = sum(fwd['header_lengths'])
        bwd_header_len = sum(bwd['header_lengths'])

        return [
            self.initiator_dest_port or 0, duration, total_fwd, total_bwd,
            total_len_fwd, total_len_bwd,
            fwd_len_max, fwd_len_min, fwd_len_mean, fwd_len_std,
            bwd_len_max, bwd_len_min, bwd_len_mean, bwd_len_std,
            total_len_fwd + (total_len_bwd / duration) if duration > 0 else 0,
            (total_fwd + total_bwd) / duration if duration > 0 else 0,
            flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
            fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
            bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,
            fwd['flags'].count(0x08),  # PSH in forward (simplified)
            bwd['flags'].count(0x08),  # PSH in backward
            fwd['flags'].count(0x20),  # URG in forward
            bwd['flags'].count(0x20),  # URG in backward
            fwd_header_len, bwd_header_len,
            fwd_pck_per_s, bwd_pck_per_s,
            pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std, pkt_len_var,
            flags['FIN'], flags['SYN'], flags['RST'], flags['PSH'], flags['ACK'], flags['URG'],
            flags['CWE'], flags['ECE'],
            down_up_ratio, avg_pkt_size, avg_fwd_seg_size, avg_bwd_seg_size,
            fwd_header_len,
            0, 0, 0, 0, 0, 0,  # Bulk features placeholders
            total_fwd, total_len_fwd, total_bwd, total_len_bwd,
            0, 0, 0, 0,  # Init win, act pkt, min seg size placeholders
            0, 0, 0, 0,  # Active window
            0, 0, 0, 0   # Idle window
        ]

    @property
    def packet_count(self):
        return len(self.packets)
