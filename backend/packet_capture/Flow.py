import time
import numpy as np
from scapy.layers.inet import IP,TCP,UDP


class Flow:
    def __init__(self, key):
        self.key = key
        self.packets = []
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.forward_packet_times = []
        self.backward_packet_times = []
        self.forward_lengths = []
        self.backward_lengths = []
        self.forward_header_lengths = []
        self.backward_header_lengths = []
        self.forward_flags = []
        self.backward_flags = []

    def add_packet(self, packet):
        now = time.time()
        direction = self.get_direction(packet)

        self.packets.append(packet)
        self.last_seen = now

        pkt_len = len(packet)
        header_len = len(packet[IP]) if IP in packet else 0

        flags = packet[TCP].flags if TCP in packet else 0

        if direction == 'forward':
            self.forward_packet_times.append(now)
            self.forward_lengths.append(pkt_len)
            self.forward_header_lengths.append(header_len)
            self.forward_flags.append(flags)
        else:
            self.backward_packet_times.append(now)
            self.backward_lengths.append(pkt_len)
            self.backward_header_lengths.append(header_len)
            self.backward_flags.append(flags)

    def get_dest_port(self):
        if self.packets:
            pkt = self.packets[0]
            if TCP in pkt or UDP in pkt:
                return pkt.dport
        return 0

    def get_direction(self, packet):
        src_ip = packet[IP].src
        return 'forward' if src_ip == self.key[0] else 'backward'

    def is_inactive(self, timeout):
        return (time.time() - self.last_seen) > timeout

    def get_duration(self):
        return self.last_seen - self.first_seen

    def compute_iat_features(self, times):
        if len(times) < 2:
            return 0, 0, 0, 0
        iats = np.diff(times)
        return np.mean(iats), np.std(iats), np.max(iats), np.min(iats)

    def compute_stats(self, lst):
        if len(lst) == 0:
            return 0, 0, 0, 0
        return max(lst), min(lst), np.mean(lst), np.std(lst)

    def compute_packet_rate(self, count):
        duration = self.get_duration()
        return count / duration if duration > 0 else 0

    def extract_features(self):
        duration = self.get_duration()
        total_fwd = len(self.forward_lengths)
        total_bwd = len(self.backward_lengths)
        total_len_fwd = sum(self.forward_lengths)
        total_len_bwd = sum(self.backward_lengths)

        fwd_len_max, fwd_len_min, fwd_len_mean, fwd_len_std = self.compute_stats(self.forward_lengths)
        bwd_len_max, bwd_len_min, bwd_len_mean, bwd_len_std = self.compute_stats(self.backward_lengths)

        flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = self.compute_iat_features(
            sorted(self.forward_packet_times + self.backward_packet_times)
        )
        fwd_iat_total = sum(np.diff(self.forward_packet_times)) if len(self.forward_packet_times) > 1 else 0
        fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = self.compute_iat_features(self.forward_packet_times)
        bwd_iat_total = sum(np.diff(self.backward_packet_times)) if len(self.backward_packet_times) > 1 else 0
        bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = self.compute_iat_features(self.backward_packet_times)

        fwd_pck_per_s = self.compute_packet_rate(total_fwd)
        bwd_pck_per_s = self.compute_packet_rate(total_bwd)

        packet_lengths = self.forward_lengths + self.backward_lengths
        pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std = self.compute_stats(packet_lengths)
        pkt_len_var = np.var(packet_lengths) if packet_lengths else 0

        fin_cnt = syn_cnt = rst_cnt = psh_cnt = ack_cnt = urg_cnt = cwe_cnt = ece_cnt = 0
        for flag_list in [self.forward_flags, self.backward_flags]:
            for flags in flag_list:
                fin_cnt += int(flags & 0x01 != 0)
                syn_cnt += int(flags & 0x02 != 0)
                rst_cnt += int(flags & 0x04 != 0)
                psh_cnt += int(flags & 0x08 != 0)
                ack_cnt += int(flags & 0x10 != 0)
                urg_cnt += int(flags & 0x20 != 0)
                cwe_cnt += 0  # Placeholder
                ece_cnt += 0  # Placeholder

        down_up_ratio = (total_bwd / total_fwd) if total_fwd > 0 else 0
        avg_pkt_size = np.mean(packet_lengths) if packet_lengths else 0
        avg_fwd_seg_size = np.mean(self.forward_lengths) if self.forward_lengths else 0
        avg_bwd_seg_size = np.mean(self.backward_lengths) if self.backward_lengths else 0
        fwd_header_len = sum(self.forward_header_lengths)

        return [
            self.get_dest_port(),duration, total_fwd, total_bwd, total_len_fwd, total_len_bwd,
            fwd_len_max, fwd_len_min, fwd_len_mean, fwd_len_std,
            bwd_len_max, bwd_len_min, bwd_len_mean, bwd_len_std,
            total_len_fwd + total_len_bwd / duration if duration > 0 else 0,
            (total_fwd + total_bwd) / duration if duration > 0 else 0,
            flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
            fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min,
            bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min,
            sum(1 for f in self.forward_flags if f & 0x08),  # Fwd PSH
            sum(1 for f in self.backward_flags if f & 0x08), # Bwd PSH
            sum(1 for f in self.forward_flags if f & 0x20),  # Fwd URG
            sum(1 for f in self.backward_flags if f & 0x20), # Bwd URG
            fwd_header_len, sum(self.backward_header_lengths),
            fwd_pck_per_s, bwd_pck_per_s,
            pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std, pkt_len_var,
            fin_cnt, syn_cnt, rst_cnt, psh_cnt, ack_cnt, urg_cnt, cwe_cnt, ece_cnt,
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