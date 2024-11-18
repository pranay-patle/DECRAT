import os
import logging
import subprocess
from datetime import datetime
from scapy.all import sniff, IP, TCP

class DECRATMonitor:
    def __init__(self):
        self.log_file = "decrat.log"
        self.capture_dir = "captures"
        self.suspicious_ports = [1337, 4444, 8080, 3389]  # Common RAT ports
        self.suspicious_keywords = ["C2", "RAT", "shell", "exec", "reverse"]
        self.packet_threshold = 10  # Threshold for triggering detection
        self.packet_counts = {}

        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format="[%(levelname)s] %(asctime)s - %(message)s",
            handlers=[logging.FileHandler(self.log_file), logging.StreamHandler()],
        )

        self.setup_capture_directory()

    def setup_capture_directory(self):
        """Ensure the capture directory exists and set appropriate permissions."""
        if not os.path.exists(self.capture_dir):
            os.makedirs(self.capture_dir, exist_ok=True)
        os.chmod(self.capture_dir, 0o777)  # Allow all users to write here

    def packet_handler(self, packet):
        """Analyze packets for suspicious activity."""
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            tcp_dport = packet[TCP].dport

            # Check for suspicious ports or traffic patterns
            if tcp_dport in self.suspicious_ports:
                logging.info(f"Suspicious port detected: {tcp_dport} from {ip_src} to {ip_dst}")
                self.increment_packet_count(ip_src)

            # Check payload for suspicious keywords (if any)
            if hasattr(packet[TCP], "payload"):
                payload = str(packet[TCP].payload)
                if any(keyword in payload for keyword in self.suspicious_keywords):
                    logging.info(f"Suspicious payload detected from {ip_src} to {ip_dst}")
                    self.increment_packet_count(ip_src)

    def increment_packet_count(self, ip):
        """Increment packet count for the given IP and trigger alert if necessary."""
        if ip not in self.packet_counts:
            self.packet_counts[ip] = 0
        self.packet_counts[ip] += 1

        if self.packet_counts[ip] >= self.packet_threshold:
            logging.info(f"Suspicious RAT activity detected from {ip}!")
            self.capture_packets(ip)
            self.packet_counts[ip] = 0  # Reset count after detection

    def capture_packets(self, ip):
        """Capture network packets using dumpcap."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_filename = os.path.join(self.capture_dir, f"capture_{timestamp}_{ip}.pcap")

        try:
            subprocess.run(
                ["dumpcap", "-i", "any", "-a", "duration:30", "-w", pcap_filename],
                check=True
            )
            logging.info(f"Packet capture saved to {pcap_filename}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to capture packets: {e}")

    def start_monitoring(self):
        """Start network monitoring."""
        logging.info("Starting network monitoring...")
        sniff(prn=self.packet_handler, store=False)


if __name__ == "__main__":
    try:
        monitor = DECRATMonitor()
        monitor.start_monitoring()
    except KeyboardInterrupt:
        logging.info("Exiting monitoring.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
