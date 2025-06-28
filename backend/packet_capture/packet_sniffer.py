from scapy.all import AsyncSniffer
import threading
import time
from backend.logging.logger import IDSLogger
from scapy.interfaces import get_working_if
from scapy.config import conf
from scapy.arch.windows import get_windows_if_list
from scapy.interfaces import get_if_list
import platform


class PacketSniffer:
    def __init__(self, interface=None, packet_callback=None):
        print("[DEBUG] Initializing PacketSniffer")
        self.interface = interface or self._select_interface()
        self.packet_callback = packet_callback or self.default_packet_handler
        self.sniff_thread = None
        self.running = False
        self.sniffer = None
        self.logger = IDSLogger()
        chosen = interface or self._select_interface()

    def _select_interface(self):
        try:
            selected_interface = get_working_if()
            return selected_interface
        except Exception:
            # Get all interfaces with their descriptions
            return self._manual_selection()

    def _manual_selection(self):
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()

        print("\nAvailable interfaces:")
        for idx, iface in enumerate(interfaces, 1):
            print(f"{idx}. {iface['win_name']} - {iface['description']}")

        if not interfaces:
            self.logger.get_logger().error("No network interfaces found.")
            return None

        while True:
            try:
                choice = int(input("Select an interface number: ")) - 1
                if 0 <= choice < len(interfaces):
                    selected_interface = interfaces[choice]['win_name']  # 👈 USE THIS!
                    print(f"[DEBUG] Selected interface: {selected_interface}")
                    return selected_interface
                else:
                    print("Invalid selection. Please choose a valid number.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except Exception as e:
                self.logger.get_logger().error(f"Error in manual selection: {str(e)}")
                return None

    def _should_stop_filter(self, _):
        return not self.running

    def start_sniffing(self):
        if not self.interface:
            self.logger.get_logger().error("No interface selected.")
            return
        if self.running:
            return

        self.running = True
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()

    def _sniff_loop(self):
        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                promisc=True,
                filter='ip',
                stop_filter=self._should_stop_filter
            )
            self.sniffer.start()
            self.sniffer.join()
        except Exception as e:
            self.logger.get_logger().error(f"Error in sniffing loop: {str(e)}", exc_info=True)
            self.running = False

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None

    def default_packet_handler(self, packet):
        print(f"[PACKET] {packet.summary()}")

    @staticmethod
    def list_friendly_interfaces():
        if platform.system() == "Windows" and get_windows_if_list:
            return [iface["name"] for iface in get_windows_if_list()]
        return get_if_list()

    @staticmethod
    def _resolve_if_name(name):
        if platform.system() == "Windows" and get_windows_if_list:
            for iface in get_windows_if_list():
                if iface["name"] == name:
                    return iface["guid"]
        return name

    def update_interface(self, new_name: str):
        if new_name == self.interface:
            self.logger.get_logger().info("Interface unchanged.")
            return
        self.logger.get_logger().info(f"Switching to interface: {new_name}")
        self.stop_sniffing()
        self.interface = new_name
        self.start_sniffing()

if __name__ == "__main__":
    sniffer = PacketSniffer()
    sniffer.start_sniffing()
    time.sleep(10)
    sniffer.stop_sniffing()