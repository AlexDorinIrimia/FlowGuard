import unittest
from unittest import mock

from backend.alerting.Notifier import format_alert_message, send_notificaton


class TestFormatAlertMessage(unittest.TestCase):

    def test_format_alert_message_valid_input(self):
        threat_type = "Port Scan"
        source_ip = "192.168.1.1"
        destination_ip = "10.0.0.2"
        protocol = "TCP"
        packet_count = 50
        confidence = 0.95

        expected_title = "[IDS ALERT] Port Scan Detected"
        expected_message = (
            "Threat Type: Port Scan\n"
            "Source IP: 192.168.1.1\n"
            "Destination IP: 10.0.0.2\n"
            "Protocol: TCP\n"
            "Packet Count: 50\n"
            "Detection Confidence: 95.00%\n"
        )

        title, message = format_alert_message(threat_type, source_ip, destination_ip, protocol, packet_count,
                                              confidence)

        self.assertEqual(title, expected_title)
        self.assertEqual(message, expected_message)

    @unittest.mock.patch("backend.alerting.Notifier.notification.notify")
    def test_send_notification_valid_input(self, mock_notify):
        title = "Test Notification"
        message = "This is a test message."
        duration = 5

        send_notificaton(title, message, duration)

        mock_notify.assert_called_once_with(
            title="Test Notification",
            message="This is a test message.",
            timeout=5,
        )

    @unittest.mock.patch("backend.alerting.Notifier.notification.notify")
    def test_send_notification_exception_handling(self, mock_notify):
        mock_notify.side_effect = Exception("Notification error")
        title = "Error Notification"
        message = "Message causing error."
        duration = 3

        with self.assertRaises(Exception) as context:
            send_notificaton(title, message, duration)

        mock_notify.assert_called_once_with(
            title=title,
            message=message,
            timeout=duration
        )

    def test_format_alert_message_zero_packet_count(self):
        threat_type = "DDoS Attack"
        source_ip = "172.16.0.1"
        destination_ip = "192.168.0.5"
        protocol = "UDP"
        packet_count = 0
        confidence = 0.80

        expected_title = "[IDS ALERT] DDoS Attack Detected"
        expected_message = (
            "Threat Type: DDoS Attack\n"
            "Source IP: 172.16.0.1\n"
            "Destination IP: 192.168.0.5\n"
            "Protocol: UDP\n"
            "Packet Count: 0\n"
            "Detection Confidence: 80.00%\n"
        )

        title, message = format_alert_message(threat_type, source_ip, destination_ip, protocol, packet_count,
                                              confidence)

        self.assertEqual(title, expected_title)
        self.assertEqual(message, expected_message)

    def test_format_alert_message_low_confidence(self):
        threat_type = "Malware"
        source_ip = "203.0.113.10"
        destination_ip = "198.51.100.20"
        protocol = "HTTP"
        packet_count = 10
        confidence = 0.02

        expected_title = "[IDS ALERT] Malware Detected"
        expected_message = (
            "Threat Type: Malware\n"
            "Source IP: 203.0.113.10\n"
            "Destination IP: 198.51.100.20\n"
            "Protocol: HTTP\n"
            "Packet Count: 10\n"
            "Detection Confidence: 2.00%\n"
        )

        title, message = format_alert_message(threat_type, source_ip, destination_ip, protocol, packet_count,
                                              confidence)

        self.assertEqual(title, expected_title)
        self.assertEqual(message, expected_message)


if __name__ == '__main__':
    unittest.main()