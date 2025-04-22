#!/usr/bin/env python3
import socket
import os
import sys
import glob
import json
import time
import argparse
from datetime import datetime


TELEMETRY_VERSION = "v2"
SOCKET_NAME = 'dpdk_telemetry.{}'.format(TELEMETRY_VERSION)
DEFAULT_PREFIX = 'rte'


def read_socket(sock, buf_len, echo=True, pretty=False):
    """ Read data from socket and return it in JSON format """
    reply = sock.recv(buf_len).decode()
    try:
        ret = json.loads(reply)
    except json.JSONDecodeError:
        print("Error in reply: ", reply)
        sock.close()
        raise
    if echo:
        indent = 2 if pretty else None
        print(json.dumps(ret, indent=indent))
    return ret


def get_dpdk_runtime_dir(fp):
    """ Using the same logic as in DPDK's EAL, get the DPDK runtime directory """
    run_dir = os.environ.get('RUNTIME_DIRECTORY')
    if not run_dir:
        if os.getuid() == 0:
            run_dir = '/var/run'
        else:
            run_dir = os.environ.get('XDG_RUNTIME_DIR', '/tmp')
    return os.path.join(run_dir, 'dpdk', fp)


def find_sockets(path):
    """ Find any possible sockets to connect to and return them """
    return glob.glob(os.path.join(path, SOCKET_NAME + '*'))


def get_telemetry_data(sock, endpoint, interface_id, buf_len):
    """ Get telemetry data for the given endpoint and interface """
    try:
        sock.send(f"{endpoint},{interface_id}".encode())
        response = read_socket(sock, buf_len, echo=False)
        return response
    except Exception as e:
        print(f"[{datetime.now()}] Error reading telemetry data: {e}", file=sys.stderr)
        return None


def detect_interfaces(sock, buf_len):
    """ Detect interfaces by querying until we get a null response """
    interface_ids = []
    interface_id = 0
    while True:
        data = get_telemetry_data(sock, "/ethdev/stats", interface_id, buf_len)
        if data and "/ethdev/stats" in data and data["/ethdev/stats"] is not None:
            interface_ids.append(interface_id)
        else:
            break
        interface_id += 1
    return interface_ids


def get_ethdev_info(sock, interface_id, buf_len):
    """ Gets detailed info about the Ethernet device """
    data = get_telemetry_data(sock, "/ethdev/info", interface_id, buf_len)
    if data and "/ethdev/info" in data and data["/ethdev/info"] is not None:
        return data["/ethdev/info"]
    return None


def human_readable(value, is_bytes=True):
    """ Convert the value to a human-readable format with K, M, G suffixes """
    suffix = "bps" if is_bytes else "pps"
    if value >= 1e9:
        return f"{value / 1e9:.2f} G{suffix}"
    elif value >= 1e6:
        return f"{value / 1e6:.2f} M{suffix}"
    elif value >= 1e3:
        return f"{value / 1e3:.2f} K{suffix}"
    else:
        return f"{value:.2f} {suffix}"


def monitor_interfaces(interval, file_prefix):
    """ Monitor interfaces' RX/TX stats and display them in real-time """
    prev_stats = {}
    ethdev_info = {}

    # Get socket path and connect
    sock_path = os.path.join(get_dpdk_runtime_dir(file_prefix), SOCKET_NAME)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        sock.connect(sock_path)
    except OSError:
        print("Error connecting to socket", file=sys.stderr)
        sys.exit(1)

    # Get output buffer length
    json_reply = read_socket(sock, 1024, echo=False)
    buf_len = json_reply["max_output_len"]

    # Detect interfaces and collect info
    interface_ids = detect_interfaces(sock, buf_len)
    if not interface_ids:
        print(f"[{datetime.now()}] No Ethernet interfaces found.", file=sys.stderr)
        return

    # Collect interface info at startup
    for interface_id in interface_ids:
        ethdev_info[interface_id] = get_ethdev_info(sock, interface_id, buf_len)

    while True:
        current_time = time.time()

        # Collect stats for each interface
        output = ["\033[H\033[J"]
        output.append(f"[{datetime.now()}] Detected interfaces: {interface_ids}")
        output.append(f"{'Interface':<12} {'Name':<20} {'RX (bps)':<20} {'TX (bps)':<20} {'RX (pps)':<15} {'TX (pps)':<15}")
        output.append("-" * 100)

        for interface_id in interface_ids:
            data = get_telemetry_data(sock, "/ethdev/stats", interface_id, buf_len)
            if data and "/ethdev/stats" in data and data["/ethdev/stats"] is not None:
                stats = data["/ethdev/stats"]
                rx_bytes = stats.get('ibytes', 0)
                tx_bytes = stats.get('obytes', 0)
                rx_packets = stats.get('ipackets', 0)
                tx_packets = stats.get('opackets', 0)

                if interface_id in prev_stats:
                    delta_time = current_time - prev_stats[interface_id]['time']
                    if delta_time > 0:
                        rx_bps = (rx_bytes - prev_stats[interface_id]['rx_bytes']) * 8 / delta_time
                        tx_bps = (tx_bytes - prev_stats[interface_id]['tx_bytes']) * 8 / delta_time
                        rx_pps = (rx_packets - prev_stats[interface_id]['rx_packets']) / delta_time
                        tx_pps = (tx_packets - prev_stats[interface_id]['tx_packets']) / delta_time
                    else:
                        # If delta_time is not greater than 0 (first iteration), show 0 stats
                        rx_bps = tx_bps = rx_pps = tx_pps = 0
                else:
                    # On first iteration, show 0 stats
                    rx_bps = tx_bps = rx_pps = tx_pps = 0

                # Collect Ethernet device name and other info
                dev_name = ethdev_info[interface_id].get('name', 'N/A') if ethdev_info.get(interface_id) else 'N/A'

                # Append stats for the current interface
                output.append(f"{interface_id:<12} "
                              f"{dev_name:<20} "
                              f"{human_readable(rx_bps):<20} "
                              f"{human_readable(tx_bps):<20} "
                              f"{human_readable(rx_pps, is_bytes=False):<15} "
                              f"{human_readable(tx_pps, is_bytes=False):<15}")

                # Update previous stats for the next iteration
                prev_stats[interface_id] = {
                    'rx_bytes': rx_bytes,
                    'tx_bytes': tx_bytes,
                    'rx_packets': rx_packets,
                    'tx_packets': tx_packets,
                    'time': current_time
                }

        # Write the collected output and flush at the end of the iteration
        sys.stdout.write("\n".join(output) + "\n")
        sys.stdout.flush()

        # Wait for the next interval
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor DPDK Ethernet interface statistics in real-time.")
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=1,
        help="Interval (in seconds) between stats collection. Default is 1 second."
    )
    parser.add_argument(
        "-f", "--file-prefix",
        type=str,
        default="rte",
        help="File prefix for setting the socket path. Default is 'rte'. The full path will be /var/run/dpdk/{file_prefix}/telemetry"
    )

    args = parser.parse_args()

    try:
        monitor_interfaces(args.interval, args.file_prefix)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.", file=sys.stderr)
