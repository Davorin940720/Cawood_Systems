import scapy.all as scapy
import nmap
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict

# Subnet of your LAN
LAN_SUBNET = "192.168.0.0/24"
ROUTER_IP = "192.168.0.1"

# Initialize the graph
G = nx.Graph()
traffic_data = defaultdict(int)

# Discover devices in the LAN using nmap
def discover_devices():
    nm = nmap.PortScanner()
    nm.scan(hosts=LAN_SUBNET, arguments='-sn')  # Ping scan to find devices
    devices = []
    for host in nm.all_hosts():
        if 'hostnames' in nm[host] and nm[host]['hostnames']:
            devices.append((host, nm[host]['hostnames'][0]))
        else:
            devices.append((host, "Unknown"))
    return devices

# Capture packets and populate traffic data
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        traffic_data[(src_ip, dst_ip)] += 1
        
        # Add edges to the graph
        G.add_edge(src_ip, dst_ip, weight=traffic_data[(src_ip, dst_ip)])

# Discover devices
devices = discover_devices()
for device, hostname in devices:
    print(f"Device found: {device} - {hostname}")
    # Add the device to the graph
    G.add_node(device, label=hostname)

# Add the router at the center
G.add_node(ROUTER_IP, label="Router")

# Start sniffing packets for a while to simulate traffic
scapy.sniff(prn=packet_callback, store=0, count=100)

# Visualize the network graph
pos = nx.spring_layout(G)
node_labels = nx.get_node_attributes(G, 'label')
node_colors = ['skyblue' if node != ROUTER_IP else 'orange' for node in G.nodes()]

plt.figure(figsize=(12, 12))
nx.draw(G, pos, with_labels=True, labels=node_labels, node_size=2000, node_color=node_colors, font_size=10, font_weight="bold", width=2, alpha=0.7)
plt.title("LAN Topology with Router in Center")
plt.show()