import pytest
from scapy.layers.inet import IP, TCP, UDP
from backend.packet_capture.FlowManager import FlowManager
from backend.packet_capture.Flow import Flow
from unittest.mock import Mock,patch


class TestFlowManager:
    def test_get_flow_key_valid_ip_tcp_packet(self):
        packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        manager = FlowManager()
        key = manager.get_flow_key(packet)
        expected_key = ("192.168.1.1", "10.0.0.1", 12345, 80, 6)  # TCP protocol is 6
        assert key == expected_key

    @pytest.fixture
    def test_process_flow_with_attack_detection(self, mocker):
        mock_flow = mocker.Mock()
        mock_detector = mocker.Mock()

        mock_flow.extract_features.return_value = [0.5, 0.3, 0.2]
        mock_detector.infer.return_value = ["Port Scan"]

        with mocker.patch("builtins.print") as mock_print:
            FlowManager.process_flow(mock_flow, mock_detector)
            mock_print.assert_called_once_with(
                "[ALERT] Attack detected: Port Scan on flow {}".format(mock_flow.key)
            )
    @pytest.fixture
    def test_process_flow_without_attack_detection(self, mocker):
        mock_flow = mocker.Mock()
        mock_detector = mocker.Mock()

        mock_flow.extract_features.return_value = [0.1, 0.2, 0.3]
        mock_detector.infer.return_value = []

        with mocker.patch("builtins.print") as mock_print:
            FlowManager.process_flow(mock_flow, mock_detector)
            mock_print.assert_not_called()

    def test_get_flow_key_valid_ip_udp_packet(self):
        packet = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53)
        manager = FlowManager()
        key = manager.get_flow_key(packet)
        expected_key = ("192.168.1.1", "10.0.0.1", 12345, 53, 17)  # UDP protocol is 17
        assert key == expected_key

    def test_get_flow_key_no_ip_packet(self):
        packet = TCP(sport=12345, dport=80)
        manager = FlowManager()
        key = manager.get_flow_key(packet)
        assert key is None

    def test_add_packet_new_flow(self):
        packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        manager = FlowManager()
        key = manager.add_packet(packet)
        expected_key = ("192.168.1.1", "10.0.0.1", 12345, 80, 6)  # TCP protocol is 6
        assert key == expected_key
        assert key in manager.flows
        assert isinstance(manager.flows[key], Flow)

    def test_add_packet_existing_flow(self):
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        manager = FlowManager()
        key1 = manager.add_packet(packet1)
        key2 = manager.add_packet(packet2)
        assert key1 == key2
        assert len(manager.flows) == 1

    def test_add_packet_invalid_packet(self):
        packet = TCP(sport=12345, dport=80)
        manager = FlowManager()
        key = manager.add_packet(packet)
        assert key is None

    def test_expire_inactive_flows(self):
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        packet2 = IP(src="192.168.2.2", dst="10.0.0.2") / UDP(sport=54321, dport=53)
        manager = FlowManager(timeout=1)
        manager.add_packet(packet1)
        manager.add_packet(packet2)

        # Mocking is_inactive method to simulate inactive flows
        manager.flows[("192.168.1.1", "10.0.0.1", 12345, 80, 6)].is_inactive = lambda timeout: True
        manager.flows[("192.168.2.2", "10.0.0.2", 54321, 53, 17)].is_inactive = lambda timeout: False

        expired_flows = manager.expire_inactive_flows()
        assert len(expired_flows) == 1
        assert expired_flows[0].key == ("192.168.1.1", "10.0.0.1", 12345, 80, 6)
        assert ("192.168.1.1", "10.0.0.1", 12345, 80, 6) not in manager.flows
        assert ("192.168.2.2", "10.0.0.2", 54321, 53, 17) in manager.flows
