from scapy.all import *
from datetime import datetime
import colorama
from colorama import Fore, Style
import sys

colorama.init()

def packet_callback(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    
    try:
        # Extract IP Layer
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            
            # Protocol Mapping
            proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, str(protocol))
            
            print(f"{Fore.CYAN}[{timestamp}]{Style.RESET_ALL} ", end="")
            print(f"{Fore.YELLOW}Src: {ip_src:15} → Dest: {ip_dst:15} ", end="")
            print(f"{Fore.GREEN}Protocol: {proto_name:6} ", end="")
            
            # Transport Layer (Ports)
            if TCP in packet:
                print(f"Port: {packet[TCP].sport} → {packet[TCP].dport} ", end="")
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    print(f"{Fore.RED}[HTTP]{Style.RESET_ALL}", end="")
            elif UDP in packet:
                print(f"Port: {packet[UDP].sport} → {packet[UDP].dport} ", end="")
            
            # Payload (if available and not too large)
            if Raw in packet and len(packet[Raw].load) > 0:
                payload = packet[Raw].load[:50]  # First 50 bytes
                try:
                    payload_str = payload.decode('utf-8', errors='ignore').strip()
                    if payload_str:
                        print(f" | Payload: {payload_str[:60]}...")
                except:
                    print(f" | Payload: (Binary Data)")
            
            print()  # New line
            
        # ICMP Packets (Ping)
        elif ICMP in packet:
            print(f"{Fore.CYAN}[{timestamp}]{Style.RESET_ALL} ", end="")
            print(f"{Fore.MAGENTA}ICMP Packet → {packet[IP].src} → {packet[IP].dst}{Style.RESET_ALL}")
            
    except Exception as e:
        pass  # Ignore packets that cause errors

def main():
    print(f"{Fore.GREEN}=== CodeAlpha Basic Network Sniffer ==={Style.RESET_ALL}")
    print("Press Ctrl+C to stop\n")
    
    # Get available interfaces
    print("Available Interfaces:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")
    
    # Ask user to select interface
    try:
        choice = int(input("\nSelect interface number: ")) - 1
        iface = interfaces[choice]
    except:
        iface = conf.iface  # Default interface
    
    print(f"\n{Fore.YELLOW}Starting sniffer on interface: {iface}{Style.RESET_ALL}\n")
    
    try:
        # Start sniffing
        sniff(iface=iface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Sniffer stopped by user.{Style.RESET_ALL}")
    except PermissionError:
        print(f"{Fore.RED}Permission Error! Run as Administrator / Root.{Style.RESET_ALL}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()