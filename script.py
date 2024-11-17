import argparse
import os
import subprocess
import pandas as pd

class PcapAnalyzer:
    def __init__(self, pcap_file, debug=False):
        self.pcap_file = pcap_file
        self.output_csv = "output.csv"
        self.suspicious_ports = [4444, 5555, 3389, 22, 9001]
        self.indicators = ["reverse shell", "metasploit", "rat", "bind shell", "meterpreter"]
        self.suspicious_activity = []
        self.debug = debug
        self.reported_pairs = set()  # Set to store unique (src_ip, dst_ip, src_mac, dst_mac)

    def convert_pcap_to_csv(self):
        """Converts the pcap file to a CSV using tshark."""
        print("[INFO] Converting pcap to csv...")
        try:
            cmd = [
                "tshark",
                "-r", self.pcap_file,
                "-T", "fields",
                "-e", "frame.time",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "eth.src",
                "-e", "eth.dst",
                "-e", "tcp.port",
                "-e", "udp.port",
                "-e", "_ws.col.Info",
                "-e", "data.text",
                "-E", "separator=,",
                "-E", "header=y",
                "-E", "quote=d"
            ]
            with open(self.output_csv, "w") as output_file:
                subprocess.run(cmd, stdout=output_file, check=True)
            print(f"[INFO] CSV file generated: {self.output_csv}")
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Failed to convert pcap to CSV: {e}")
            raise

    def analyze_csv(self):
        """Analyzes the CSV file for potential threats."""
        print("[INFO] Analyzing CSV for suspicious activity...")
        try:
            data = pd.read_csv(self.output_csv, on_bad_lines="skip")
            if data.empty:
                print("[INFO] CSV file is empty. No data to analyze.")
                return

            for index, row in data.iterrows():
                try:
                    src_ip = row.get("ip.src", "")
                    dst_ip = row.get("ip.dst", "")
                    src_mac = row.get("eth.src", "")
                    dst_mac = row.get("eth.dst", "")
                    tcp_port = row.get("tcp.port", "")
                    udp_port = row.get("udp.port", "")
                    info = str(row.get("_ws.col.Info", "")).lower()
                    data_text = str(row.get("data.text", "")).lower()

                    # Debugging: Print processed row details
                    if self.debug:
                        print(f"[DEBUG] Row {index}: {row}")

                    # Unique identifier for the pair (src_ip, dst_ip, src_mac, dst_mac)
                    pair_key = (src_ip, dst_ip, src_mac, dst_mac)
                    
                    # Skip if this pair has already been reported
                    if pair_key in self.reported_pairs:
                        continue
                    
                    # Initialize activity detection
                    activity_detected = False
                    details = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_mac": src_mac,
                        "dst_mac": dst_mac,
                        "ports": [],
                        "indicators": [],
                    }

                    # Detect suspicious ports
                    if any(str(port) in info for port in self.suspicious_ports):
                        details["ports"].append(f"Port {tcp_port}/{udp_port}")
                        activity_detected = True

                    # Detect suspicious indicators
                    if any(indicator in info for indicator in self.indicators):
                        details["indicators"].append(info)
                        activity_detected = True

                    if activity_detected:
                        self.suspicious_activity.append(details)
                        self.reported_pairs.add(pair_key)  # Add the pair to the set

                except Exception as row_error:
                    if self.debug:
                        print(f"[DEBUG] Failed to process row {index}: {row_error}")

            if self.suspicious_activity:
                print("\n[ALERT] Suspicious activity detected!")
                self.report_incidents()
            else:
                print("[INFO] No suspicious activity found.")

        except Exception as e:
            print(f"[ERROR] Failed to analyze CSV: {e}")

    def report_incidents(self):
        """Prints a summary of suspicious activities."""
        print("[SUMMARY] Detected suspicious activity:")
        for activity in self.suspicious_activity:
            print("\n--- Suspicious Incident ---")
            for key, value in activity.items():
                print(f"{key.capitalize()}: {', '.join(value) if isinstance(value, list) else value}")

def main():
    parser = argparse.ArgumentParser(description="Analyze PCAP files for suspicious activity.")
    parser.add_argument("-i", "--input", required=True, help="Input PCAP file")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[ERROR] File '{args.input}' not found.")
        return

    analyzer = PcapAnalyzer(pcap_file=args.input, debug=args.debug)
    try:
        analyzer.convert_pcap_to_csv()
        analyzer.analyze_csv()
    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")

if __name__ == "__main__":
    main()
