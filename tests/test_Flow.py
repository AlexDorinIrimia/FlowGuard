import time
from unittest.mock import MagicMock, patch
from scapy.layers.inet import IP, TCP, UDP

import pytest
from backend.packet_capture.Flow import Flow


class TestFlow:
    @pytest.fixture
    def flow_instance(self):
        return Flow(key=("192.168.1.1", 8080, "10.0.0.1", "TestFlow"))

    def test_add_packet_forward_direction(self, flow_instance):
        packet = MagicMock()
        packet[IP].src = "192.168.1.1"
        packet[IP].len = 150
        packet[TCP].flags = 0x10

        flow_instance.add_packet(packet)

        assert len(flow_instance.forward_packet_times) == 1
        assert len(flow_instance.forward_lengths) == 1
        assert len(flow_instance.forward_flags) == 1

    def test_add_packet_backward_direction(self, flow_instance):
        packet = MagicMock()
        packet[IP].src = "10.0.0.1"
        packet[IP].len = 200
        packet[TCP].flags = 0x20

        flow_instance.add_packet(packet)

        assert len(flow_instance.backward_packet_times) == 1
        assert len(flow_instance.backward_lengths) == 1
        assert len(flow_instance.backward_flags) == 1

    def test_is_inactive(self, flow_instance):
        with patch("time.time", return_value=flow_instance.last_seen + 5):
            result = flow_instance.is_inactive(timeout=4)
        assert result is True

    def test_get_duration(self, flow_instance):
        initial_time = flow_instance.first_seen
        with patch('time.time', return_value=initial_time + 7):
            duration = flow_instance.get_duration()
        assert duration == 7

    def test_extract_features(self, flow_instance):
        packet1 = MagicMock()
        packet1[IP].src = "192.168.1.1"
        packet1[IP].len = 150
        packet1[TCP].flags = 0x10

        packet2 = MagicMock()
        packet2[IP].src = "10.0.0.1"
        packet2[IP].len = 200
        packet2[TCP].flags = 0x20

        flow_instance.add_packet(packet1)
        flow_instance.add_packet(packet2)

        features = flow_instance.extract_features()
        assert isinstance(features, list)
        assert len(features) > 0
