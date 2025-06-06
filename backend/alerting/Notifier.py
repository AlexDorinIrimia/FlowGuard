from plyer import notification

def format_alert_message(threat_type: str, source_ip: str, destination_ip: str, protocol: str,
                         packet_count: int, confidence: float) -> tuple:

    title = f"[IDS ALERT] {threat_type} Detected"
    message = (
        f"Threat Type: {threat_type}\n"
        f"Source IP: {source_ip}\n"
        f"Destination IP: {destination_ip}\n"
        f"Protocol: {protocol}\n"
        f"Packet Count: {packet_count}\n"
        f"Detection Confidence: {confidence * 100:.2f}%\n"
    )
    return title, message

def send_notificaton(title: str, message: str, duration:int):
    try:
        notification.notify(
            title=title,
            message=message,
            timeout=duration,
        )
    except Exception as e:
        print("[ERROR] Failed to send notification.")
        raise
