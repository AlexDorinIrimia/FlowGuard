import time
from collections import defaultdict
from plyer import notification

class AlertManager:
    def __init__(self, alert_interval=300, severity_threshold="medium"):
        """
        alert_interval: secunde, minim între notificări pentru același tip de alertă
        severity_threshold: nivel minim de severitate care declanșează notificarea
        """
        self.alert_interval = alert_interval
        self.severity_threshold = severity_threshold
        self.severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        self.last_alert_time = defaultdict(lambda: 0)

    def send_notification(self, alert):
        """Trimite efectiv notificarea (email, SMS, log etc.)"""
        title = f"IDS Alert: {alert['type']} ({alert['severity']})"
        message = f"Source: {alert['src_ip']}\nTarget: {alert['dst_ip']}"
        notification.notify(
            title=title,
            message=message,
            timeout=10  # durata în secunde a notificării
        )

    def process_alert(self, alert):
        """
        Procesează alerta, aplică filtrarea pe severitate și rate limiting
        alert: dict cu cel puțin 'type', 'severity', 'src_ip', 'dst_ip'
        """
        now = time.time()
        alert_type = alert['type']
        severity = alert.get('severity', 'low')

        # Filtrare pe severitate
        if self.severity_levels.get(severity, 0) < self.severity_levels.get(self.severity_threshold, 2):
            return  # ignoră alertele prea puțin critice

        # Rate limiting
        if now - self.last_alert_time[alert_type] >= self.alert_interval:
            self.send_notification(alert)
            self.last_alert_time[alert_type] = now
        else:
            print(f"Skipping alert {alert_type}, sent too recently.")