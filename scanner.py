import socket
import argparse
import threading
import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor

lock = threading.Lock()


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    631: "IPP",
    3306: "MYSQL",
    5432: "POSTGRESQL",
    6379: "REDIS",
    8000: "HTTP-ALT",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9001: "HTTP-ALT"
}


# -------------------------
# UTIL
# -------------------------
def clean_banner(banner):
    text = banner.decode(errors="ignore")
    printable = "".join(c for c in text if c.isprintable())
    return " ".join(printable.split())[:120]


def grab_banner(sock):
    try:
        sock.settimeout(1.5)
        banner = sock.recv(1024)
        if banner:
            return clean_banner(banner)
    except:
        pass
    return None


def get_http_server(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))

        req = (
            f"HEAD / HTTP/1.0\r\n"
            f"Host: {target}\r\n"
            f"\r\n"
        )

        sock.send(req.encode())

        response = sock.recv(4096).decode(errors="ignore")
        sock.close()

        for line in response.splitlines():
            if line.lower().startswith("server:"):
                return line.split(":", 1)[1].strip()

    except:
        pass

    return None


def is_host_up(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.4)

        result = sock.connect_ex((str(ip), 80))

        sock.close()

        return result == 0
    except:
        return False


# -------------------------
# SCAN CORE
# -------------------------
def scan_port(target, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        if sock.connect_ex((target, port)) == 0:

            service = COMMON_SERVICES.get(port, "UNKNOWN")
            banner = grab_banner(sock)

            http_ports = {80, 443, 8000, 8080, 8443, 9001}
            server = None

            if port in http_ports:
                server = get_http_server(target, port)

            data = {
                "port": port,
                "service": service,
                "banner": banner,
                "server": server
            }

            with lock:
                if target not in results:
                    results[target] = []
                results[target].append(data)

        sock.close()

    except:
        pass


def scan_host(host, start_port, end_port, port_threads, results):
    with ThreadPoolExecutor(max_workers=port_threads) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, host, port, results)


# -------------------------
# MAIN
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Mini Nmap-like Scanner (CIDR + JSON output)")

    parser.add_argument("target", help="IP or CIDR (ex: 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", default="1-1024")
    parser.add_argument("-t", "--threads", type=int, default=100)
    parser.add_argument("-o", "--output", help="Output file (.json or .txt)")

    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split("-"))

    print(f"[*] Target : {args.target}")
    print(f"[*] Ports  : {start_port}-{end_port}")
    print(f"[*] Threads: {args.threads}\n")

    # -------------------------
    # HOST DISCOVERY
    # -------------------------
    targets = []

    try:
        network = ipaddress.ip_network(args.target, strict=False)

        print(f"[*] CIDR detected: {network}")
        print("[*] Running host discovery...\n")

        for ip in network.hosts():
            if is_host_up(ip):
                print(f"[+] Host up: {ip}")
                targets.append(str(ip))

    except ValueError:
        targets = [args.target]

    results = {}

    # -------------------------
    # HOST THREADS
    # -------------------------
    host_threads = min(50, len(targets) if targets else 1)

    print(f"\n[*] Host threads: {host_threads}")

    with ThreadPoolExecutor(max_workers=host_threads) as executor:
        for host in targets:
            print(f"\n[*] Scanning host: {host}")
            executor.submit(scan_host, host, start_port, end_port, args.threads, results)

    # -------------------------
    # OUTPUT STRUCTURE
    # -------------------------
    output_json = {}

    for host, ports in results.items():
        output_json[host] = []

        print(f"\n=== {host} ===")

        for r in sorted(ports, key=lambda x: x["port"]):

            entry = {
                "port": r["port"],
                "service": r["service"],
                "banner": r["banner"],
                "server": r["server"]
            }

            output_json[host].append(entry)

            print(f"[+] {r['port']}/tcp OPEN ({r['service']})")

            if r["banner"]:
                print(f"    Banner: {r['banner']}")

            if r["server"]:
                print(f"    Server: {r['server']}")

    # -------------------------
    # SAVE OUTPUT
    # -------------------------
    if args.output:

        if args.output.endswith(".json"):
            with open(args.output, "w") as f:
                json.dump(output_json, f, indent=4)

        else:
            with open(args.output, "w") as f:
                for host, ports in output_json.items():
                    f.write(f"\n=== {host} ===\n")

                    for r in ports:
                        f.write(f"[+] {r['port']}/tcp OPEN ({r['service']})\n")

                        if r["banner"]:
                            f.write(f"    Banner: {r['banner']}\n")

                        if r["server"]:
                            f.write(f"    Server: {r['server']}\n")

        print(f"\n[*] Saved to {args.output}")


if __name__ == "__main__":
    main()
