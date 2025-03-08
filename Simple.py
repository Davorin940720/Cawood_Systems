import scapy.all as scapy
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict

# Create a graph object
G = nx.Graph()
traffic_data = defaultdict(int)

# Packet capture function
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        traffic_data[(src_ip, dst_ip)] += 1
        
        # Add nodes and edges to the graph
        G.add_edge(src_ip, dst_ip, weight=traffic_data[(src_ip, dst_ip)])

# Start sniffing packets
scapy.sniff(prn=packet_callback, store=0, count=100)

# Draw the network graph
pos = nx.spring_layout(G)
nx.draw(G, pos, with_labels=True, node_size=1000, node_color="skyblue", font_size=10, font_weight="bold", width=1, alpha=0.7)
plt.show()