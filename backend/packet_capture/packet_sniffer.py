from scapy.all import AsyncSniffer
import threading

class PacketSniffer:
    def __init__(self, interface=None, packet_callback=None):
        print("[DEBUG] Initializing PacketSniffer")
        self.interface = interface
        self.packet_callback = packet_callback or self.default_packet_handler
        self.sniff_thread = None
        self.running = False
        self.sniffer = None
        self.lock = threading.Lock()

    def start_sniffing(self):
        if self.running:
            return
        self.running = True
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

    def _sniff_loop(self):
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self.packet_callback,
            store=False,
            promisc=True
        )
        self.sniffer.start()
        self.sniffer.join()

    def stop_sniffing(self):
        with self.lock:
            if self.sniffer:
                self.sniffer.stop()
                self.sniffer = None
            self.running = False
            if self.sniff_thread and self.sniff_thread.is_alive():
                self.sniff_thread.join()

    @staticmethod
    def default_packet_handler(packet):
        print(f"[PACKET] {packet.summary()}")