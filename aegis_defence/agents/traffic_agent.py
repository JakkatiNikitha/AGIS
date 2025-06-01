"""
Traffic monitoring and analysis agent for AGIS.
"""

import scapy.all as scapy
from datetime import datetime
import threading
import queue
import logging

class TrafficAgent:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.is_running = False
        self.logger = logging.getLogger(__name__)
        
    def start_monitoring(self, interface=None):
        """Start monitoring network traffic."""
        self.is_running = True
        self.monitor_thread = threading.Thread(target=self._monitor_traffic)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop monitoring network traffic."""
        self.is_running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join()
            
    def _monitor_traffic(self):
        """Internal method to monitor and analyze traffic."""
        try:
            scapy.sniff(
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: not self.is_running
            )
        except Exception as e:
            self.logger.error(f"Traffic monitoring error: {str(e)}")
            
    def _packet_callback(self, packet):
        """Process captured packets."""
        try:
            if packet.haslayer(scapy.IP):
                packet_info = {
                    'timestamp': datetime.now(),
                    'src_ip': packet[scapy.IP].src,
                    'dst_ip': packet[scapy.IP].dst,
                    'protocol': packet[scapy.IP].proto,
                    'length': len(packet)
                }
                self.packet_queue.put(packet_info)
        except Exception as e:
            self.logger.error(f"Packet processing error: {str(e)}")
            
    def get_traffic_stats(self):
        """Get current traffic statistics."""
        stats = {
            'packets_processed': self.packet_queue.qsize(),
            'is_monitoring': self.is_running
        }
        return stats 