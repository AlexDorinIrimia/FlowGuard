from unittest.mock import Mock, patch

import pytest
from backend.packet_capture.packet_sniffer import PacketSniffer
from scapy.layers.inet import IP


class TestPacketSniffer:
    @pytest.fixture
    def packet_sniffer(self):
        return PacketSniffer()

    def test_default_initialization(self, packet_sniffer):
        assert packet_sniffer.interface is not None
        assert callable(packet_sniffer.packet_callback)
        assert packet_sniffer.running is False
        assert packet_sniffer.sniff_thread is None

    def test_start_sniffing_without_interface(self):
        sniffer = PacketSniffer(interface=None)
        sniffer._select_interface = Mock(return_value=None)
        sniffer.start_sniffing()
        assert sniffer.running is False

    @patch('backend.packet_capture.packet_sniffer.sniff')
    def test_start_sniffing(self, mock_sniff):
        sniffer = PacketSniffer(interface='eth0')
        sniffer.start_sniffing()
        assert sniffer.running is True
        sniffer.stop_sniffing()

    @patch('backend.packet_capture.packet_sniffer.sniff', side_effect=Exception("Sniff error"))
    def test_sniffing_error_handling(self, mock_sniff):
        sniffer = PacketSniffer(interface='eth0')
        sniffer.start_sniffing()
        assert sniffer.running is False

    def test_stop_sniffing(self):
        sniffer = PacketSniffer(interface='eth0')
        sniffer.start_sniffing()
        sniffer.stop_sniffing()
        assert not sniffer.running
        assert sniffer.sniff_thread is not None
        assert not sniffer.sniff_thread.is_alive()

    def test_packet_callback(self, packet_sniffer):
        custom_callback = Mock()
        sniffer = PacketSniffer(interface='eth0', packet_callback=custom_callback)
        dummy_packet = IP(src="192.168.1.1", dst="10.0.0.1")
        sniffer.packet_callback(dummy_packet)
        custom_callback.assert_called_once_with(dummy_packet)

    def test_default_packet_handler(self, capsys):
        packet = IP(src="192.168.1.1", dst="10.0.0.1")
        sniffer = PacketSniffer(interface='eth0')
        sniffer.default_packet_handler(packet)
        captured = capsys.readouterr()
        assert "[PACKET]" in captured.out
        assert "192.168.1.1" in captured.out
        assert "10.0.0.1" in captured.out

    def test_select_interface_with_mocked_list(self):
        with patch('backend.packet_capture.packet_sniffer.get_if_list', return_value=['eth0', 'eth1']) as mock_if_list:
            with patch('backend.packet_capture.packet_sniffer.IFACES',
                       {'eth0': Mock(name='eth0'), 'eth1': Mock(name='eth1')}):
                with patch('builtins.input', side_effect=['1']):
                    sniffer = PacketSniffer(interface=None)
                    # Force interface selection
                    sniffer._select_interface()
                    # Verify the mock was called and interface was selected
                    assert mock_if_list.called
                    assert sniffer.interface is not None

