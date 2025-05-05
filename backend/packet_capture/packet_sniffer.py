from scapy.all import *
import ctypes
import sys

def run_as_admin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return

    script = sys.argv[0]
    params = " ".join([script] + sys.argv[1:])

    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit()

class PacketSniffer:
    def __init__(self):
        self.interface = self.get_interface()

    def get_interface(self):
        try:
            iface = get_working_if()
            if iface:
                return iface
        except Exception:
            pass

        interfaces = get_if_list()
        print("Available Interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"{i + 1}. {iface}")

        while True:
            try:
                choice = int(input("Select an interface number: ")) - 1
                if 0 <= choice < len(interfaces):
                    return interfaces[choice]
                else:
                    print("Invalid selection. Please choose a valid number.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    def start_sniffing(self):
        print(f"Sniffing on: {self.interface}")
        sniff(iface=self.interface, prn=self.packet_handler, store=False)

    @staticmethod
    def packet_handler(packet):
        print(f"Captured Packet: {packet.summary()}")

if __name__ == "__main__":
    sniffer = PacketSniffer()
    sniffer.start_sniffing()




