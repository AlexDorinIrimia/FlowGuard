from scapy.all import *
import threading
import time


class PacketSniffer:
    def __init__(self, interface=None, packet_callback=None):
        print("[DEBUG] Initializing PacketSniffer")
        self.interface = interface or self._select_interface()
        self.packet_callback = packet_callback or self.default_packet_handler
        self.sniff_thread = None
        self.running = False
        self.sniffer = None
        print(f"[DEBUG] Initialized with interface: {self.interface}")

    def _select_interface(self):
        """Auto-detect or prompt the user to select a network interface."""
        print("[DEBUG] Selecting interface")
        try:
            selected_interface = get_working_if()
            return selected_interface
        except Exception:
            # Get all interfaces with their descriptions
            return self._manual_selection()
        finally:
            print("[DEBUG] Interface selection completed")

    def _manual_selection(self):
        from scapy.arch.windows import get_windows_if_list  # For Windows
        interfaces = get_windows_if_list()
        print("\nAvailable interfaces:")
        for idx, iface in enumerate(interfaces, 1):
            print(f"{idx}. {iface['name']} - {iface['description']}")
        if not interfaces:
            print("[ERROR] No network interfaces found!")
            return None
        while True:
            try:
                choice = int(input("Select an interface number: ")) - 1
                if 0 <= choice < len(interfaces):
                    selected_interface = interfaces[choice]['name']
                    print(f"[DEBUG] Selected interface: {selected_interface}")
                    return selected_interface
                else:
                    print("Invalid selection. Please choose a valid number.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except Exception as e:
                print(f"[ERROR] Error in interface selection: {str(e)}")
                return None

    def _should_stop_filter(self, _):
        return not self.running

    def start_sniffing(self):
        """Start the packet sniffer."""
        print("[DEBUG] Starting sniffing process")

        if not self.interface:
            print("[ERROR] No interface selected!")
            return

        if self.running:
            print("[DEBUG] Sniffer is already running")
            return

        try:
            print(f"[+] Starting sniffing on interface: {self.interface}")
            self.sniff_thread = threading.Thread(target=self._sniff_loop)
            self.sniff_thread.daemon = True
            print("[DEBUG] Starting sniff thread")
            self.sniff_thread.start()
            print("[DEBUG] Sniff thread started")
            self.running = True
        except Exception as e:
            print(f"[ERROR] Failed to start sniffing: {str(e)}")
            self.running = False

    def _sniff_loop(self):
        """Internal method for sniffing loop."""
        print("[DEBUG] Entered sniff loop")
        try:
            print("[DEBUG] Starting Scapy sniff")
            self.sniffer = sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                stop_filter=self._should_stop_filter
            )
            print("[DEBUG] Scapy sniff completed")
        except Exception as e:
            print(f"[ERROR] Error in sniffing loop: {str(e)}")
            self.running = False

    def stop_sniffing(self):
        """Stop sniffing cleanly."""
        print("[DEBUG] Stopping sniffer")
        self.running = False

        if self.sniff_thread and self.sniff_thread.is_alive():
            try:
                print("[DEBUG] Joining sniff thread")
                self.sniff_thread.join(timeout=2)
                if self.sniff_thread.is_alive():
                    print("[WARNING] Sniffer thread did not stop gracefully")
            except Exception as e:
                print(f"[ERROR] Error stopping sniffer: {str(e)}")
        print("[DEBUG] Sniffer stopped")

    def default_packet_handler(self, packet):
        """Default packet handler if none is provided"""
        print(f"[PACKET] {packet.summary()}")


if __name__ == "__main__":
    sniffer = PacketSniffer()
    sniffer.start_sniffing()
    time.sleep(10)
    sniffer.stop_sniffing()