import socket
import struct
import time
import select
import sys


def calculate_checksum(data):
    sum = 0
    count_to = (len(data) // 2) * 2
    count = 0

    while count < count_to:
        this_val = data[count + 1] * 256 + data[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(data):
        sum = sum + data[-1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_icmp_message(sequence):
    message_type = 8  # Echo Request
    message_code = 0
    checksum_value = 0
    identifier = 54321

    header = struct.pack("!BBHHH", message_type, message_code, checksum_value, identifier, sequence)

    timestamp = struct.pack("!d", time.time())
    seq_little = struct.pack("<H", sequence)
    seq_big = struct.pack(">H", sequence)

    payload = timestamp + seq_little + seq_big

    checksum_value = calculate_checksum(header + payload)

    header = struct.pack("!BBHHH", message_type, message_code, checksum_value, identifier, sequence)

    return header + payload



def tracert(dest_addr, max_hops=30, timeout=1, attempts_per_hop=3):
    try:
        dest_ip = socket.gethostbyname(dest_addr)
        print(f"Tracing route to {dest_addr} [{dest_ip}] with maximum of {max_hops} hops:")
    except socket.gaierror:
        print(f"Error: Could not resolve hostname {dest_addr}")
        return

    sequence = 0

    for hop in range(1, max_hops + 1):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        sender.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, hop)
        receiver.settimeout(timeout)
        receiver.bind(("", 0))

        response_times = []
        response_address = None

        for attempt in range(attempts_per_hop):
            message = build_icmp_message(sequence)
            sequence += 1

            send_time = time.time()
            sender.sendto(message, (dest_ip, 1))

            ready = select.select([receiver], [], [], timeout)
            if ready[0]:
                received_message, response_address = receiver.recvfrom(512)
                receive_time = time.time()
                response_times.append((receive_time - send_time) * 1000)
            else:
                response_times.append(None)

        sender.close()
        receiver.close()

        if response_address:
            response_address = response_address[0]
            times_str = "  ".join(f"{t:.2f} ms" if t else "*" for t in response_times)
            print(f"{hop:2} {times_str} {response_address}")
        else:
            print(f"{hop:2} *  *  * Request timed out.")

        if response_address == dest_ip:
            break



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python trace_route.py <hostname or IP address>")
        sys.exit(1)

    target = sys.argv[1]
    tracert(target)
