import numpy as np
from scapy.layers.inet import IP, TCP, UDP
import time

class Flow:
    def __init__(self, key, retrans_delay=5):
        self.key = key
        self.packets = []
        self.first_seen = None
        self.last_seen = None
        self.finished = False
        self.initiator_dest_port = None
        self.initiator_ip = None
        self.responder_ip = None

        self.data = {
            'forward': {'times': [], 'lengths': [], 'header_lengths': [], 'flags': []},
            'backward': {'times': [], 'lengths': [], 'header_lengths': [], 'flags': []}
        }

    def add_packet(self, packet):
        if packet is None or IP not in packet:
            return

        direction = self.get_direction(packet)
        now = getattr(packet, "time", time.time())
        self.packets.append(packet)

        if self.first_seen is None:
            self.first_seen = now
            self.initiator_ip = packet[IP].src
            self.responder_ip = packet[IP].dst
        self.last_seen = now

        pkt_len = len(packet)
        header_len = len(packet[IP])
        flags = 0
        # FIN sau RST
        if flags & 0x01 or flags & 0x04:
            self.finished = True

        # Set initiator dest port
        if self.initiator_dest_port is None and direction == 'forward':
            if TCP in packet:
                self.initiator_dest_port = packet[TCP].dport
            elif UDP in packet:
                self.initiator_dest_port = packet[UDP].dport

        self.data[direction]['times'].append(now)
        self.data[direction]['lengths'].append(pkt_len)
        self.data[direction]['header_lengths'].append(header_len)
        self.data[direction]['flags'].append(flags)


    def get_direction(self, packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sport = dport = None
        if TCP in packet:
            sport, dport = packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            sport, dport = packet[UDP].sport, packet[UDP].dport

        key_forward = (self.key[0], self.key[1])
        if (src_ip, sport) == key_forward:
            return 'forward'
        return 'backward'

    def get_duration(self):
        if self.first_seen is None or self.last_seen is None:
            return 0
        return self.last_seen - self.first_seen

    def compute_iat_mean(self, times):
        if len(times) < 2:
            return 0
        return np.mean(np.diff(np.array(times, dtype=float)))

    def count_flag(self, direction, flag_mask):
        return sum(bool(flag & flag_mask) for flag in self.data[direction]['flags'])

    @property
    def packet_count(self):
        return len(self.packets)

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
        fwd_pkt_std = np.std(fwd['lengths']) if fwd['lengths'] else 0
        bwd_pkt_mean = np.mean(bwd['lengths']) if bwd['lengths'] else 0
        bwd_pkt_min = min(bwd['lengths']) if bwd['lengths'] else 0
        bwd_pkt_std = np.std(bwd['lengths']) if bwd['lengths'] else 0

        bwd_hdr_len = sum(bwd['header_lengths'])
        fwd_hdr_len = sum(fwd['header_lengths'])

        subflow_bwd_pkts = len(bwd['lengths'])
        subflow_bwd_bytes = total_len_bwd
        flow_bps = (total_len_fwd + total_len_bwd) / duration if duration > 0 else 0
        flow_iat_mean = self.compute_iat_mean(fwd['times'] + bwd['times'])
        avg_bwd_seg_size = total_len_bwd / subflow_bwd_pkts if subflow_bwd_pkts > 0 else 0

        # TCP flag counts
        fin_flag_cnt = self.count_flag('forward', 0x01) + self.count_flag('backward', 0x01)
        syn_flag_cnt = self.count_flag('forward', 0x02) + self.count_flag('backward', 0x02)
        rst_flag_cnt = self.count_flag('forward', 0x04) + self.count_flag('backward', 0x04)
        psh_flag_cnt = self.count_flag('forward', 0x08) + self.count_flag('backward', 0x08)
        ack_flag_cnt = self.count_flag('forward', 0x10) + self.count_flag('backward', 0x10)
        urg_flag_cnt = self.count_flag('forward', 0x20) + self.count_flag('backward', 0x20)
        ece_flag_cnt = self.count_flag('forward', 0x40) + self.count_flag('backward', 0x40)
        cwr_flag_cnt = self.count_flag('forward', 0x80) + self.count_flag('backward', 0x80)

        return [
            self.initiator_dest_port or 0, duration, total_len_fwd, fwd_pkt_max, fwd_pkt_mean, fwd_pkt_std,
            bwd_pkt_min, bwd_pkt_mean, bwd_pkt_std, bwd_hdr_len, max_pkt_len, pkt_len_std, avg_pkt_size,
            avg_bwd_seg_size, subflow_bwd_pkts, subflow_bwd_bytes, flow_bps, flow_iat_mean,
            fin_flag_cnt, syn_flag_cnt, rst_flag_cnt, psh_flag_cnt, ack_flag_cnt, urg_flag_cnt, ece_flag_cnt,
            cwr_flag_cnt, fwd_hdr_len
        ]