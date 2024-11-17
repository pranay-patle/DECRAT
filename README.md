# DECRAT - Detection of Remote Access Tools

DECRAT (Detection of Remote Access Tools) is a Python framework developed to identify the presence of Remote Access Tools (RATs) and Metasploit payloads in network traffic. By analyzing pcap files, DECRAT enables forensic and cybersecurity analysts to detect suspicious remote access activity, providing insights into potential security threats and helping in investigations.

## Table of Contents
- [Project Overview](#project-overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Methodology](#methodology)


## Project Overview

DECRAT is designed to process network traffic captures in pcap format, converting them to CSV files for analysis. The framework identifies suspicious patterns indicative of RATs, reverse shells, and other unauthorized remote access tools. DECRAT can be used in digital forensic investigations and is designed with adherence to chain-of-custody standards.

## Features

- **PCAP to CSV Conversion**: Uses `tshark` to convert pcap files to a CSV format for easy processing.
- **RAT Detection**: Identifies potential remote access tools and Metasploit payload activity.
- **Suspicious Activity Report**: Outputs an analysis report highlighting possible remote access and suspicious communications.
- **Debug Mode**: Provides a detailed log of each analyzed row for in-depth investigation.

## Installation

To install DECRAT, ensure you have the following prerequisites installed:
- **Python 3.6+**
- **Tshark** (Wireshark command-line utility for packet analysis)
- **pandas** (Python library for data manipulation)

### Steps

1. **Clone the Repository**
    ```bash
    git clone https://github.com/pranay-patle/DECRAT.git
    cd DECRAT
    ```

2. **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: Ensure `tshark` is installed on your system. If not, [download it here](https://www.wireshark.org/#download)).*

## Usage

To use DECRAT, run the script with the following options:

```bash
python decrat.py -i <input_pcap_file> [--debug]
```
- -i, --input: The input pcap file for analysis.
- --debug: Optional flag for detailed output.
Example
```bash
python decrat.py -i capture.pcap --debug
```
Upon successful execution, DECRAT will generate a CSV file named output.csv and output a report summarizing any suspicious remote access activity detected in the network traffic.

## Methodology
The DECRAT framework follows these steps:


- **PCAP to CSV Conversion**: The captured network traffic is converted to CSV format.
- **Data Analysis**: The CSV file is analyzed for indicators of RAT and unauthorized access, such as specific ports, keywords, and patterns related to remote access tools.
- **Report Generation**: A summary of any suspicious activities is generated, indicating potential RAT or Metasploit payload detections.


