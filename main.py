import argparse
import random
import socket
import time
import errno
import struct
import os
import sys
import ipaddress
import concurrent.futures

from scapy.all import IP, TCP, ICMP, sr1, send

def make_dns_query():
    transaction_id = random.getrandbits(16)
    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        0x0100,  # обычный запрос
        1,       # один вопрос
        0, 0, 0)
    question = (b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1))
    return transaction_id, header + question


def is_dns_response(data, transaction_id):
    if len(data) < 12:
        return False
    response_id, flags = struct.unpack("!HH", data[:4])
    return response_id == transaction_id and bool(flags & 0x8000)


def recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            return None
        result.extend(chunk)
    return bytes(result)


def guess_tcp_protocol(ip, port, timeout): #распознает HTTP DNS ECHO поверх TCP
    # HTTP
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = (
                f"GET / HTTP/1.0\r\n"
                f"Host: {ip}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            sock.sendall(request)
            if sock.recv(1024).startswith(b"HTTP/"):
                return "HTTP"
    except OSError:
        pass

    # DNS
    transaction_id, query = make_dns_query()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(struct.pack("!H", len(query)) + query)
            size_data = recv_exact(sock, 2)
            if size_data:
                response_size = struct.unpack("!H", size_data)[0]
                if response_size >= 12:
                    response = recv_exact(sock, response_size)
                    if response and is_dns_response(response, transaction_id):
                        return "DNS"
    except OSError:
        pass

    #Echo
    token = b"portscan-echo-" + os.urandom(16)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(token)
            if recv_exact(sock, len(token)) == token:
                return "ECHO"
    except OSError:
        pass
    return None


def scan_TCP(ip, port, timeout=2, do_guess=False):
    source_port = random.randrange(49152, 65536)
    source_seq = random.getrandbits(32)

    ip_packet = IP(dst=ip)
    tcp_packet = TCP(sport=source_port, dport=port, flags="S", seq=source_seq, )
    syn_packet = ip_packet / tcp_packet

    start = time.monotonic()

    try:
        response = sr1(syn_packet, timeout=timeout, verbose=0)
    except Exception as e:
        return "error", None, None, str(e)

    d_t_ms = (time.monotonic() - start) * 1000
    if response is None:
        return "фильтрация/хз, потеряли", d_t_ms, None, None
    if response.haslayer(ICMP):
        return "фильтрация", d_t_ms, None, None

    tcp_rep = response.getlayer(TCP)
    ip_rep = response.getlayer(IP)
    if ip_rep.src != ip or tcp_rep is None or ip_rep is None:
        return "unknown", d_t_ms, None, None
    if tcp_rep.sport != port or tcp_rep.dport != source_port:
        return "unknown", d_t_ms, None, None

    flags = int(tcp_rep.flags)
    if (flags & 0x12) == 0x12 and (tcp_rep.ack == ((source_seq + 1) & 0xFFFFFFFF)):
        ip2_packet = IP(src=ip_rep.dst, dst=ip_rep.src)
        tsp2_packet = TCP(sport=source_port, dport=port, flags="R", seq=tcp_rep.ack)
        rst_packet = ip2_packet / tsp2_packet

        error = None
        try:
            send(rst_packet, verbose=0)
        except Exception as e:
            error = f"open, но не удалось отправить RST: {e}"

        app_protocol = (
            guess_tcp_protocol(ip, port, timeout)
            if do_guess
            else None
        )
        return "open", d_t_ms, app_protocol, error

    if flags & 0x04:
        return "closed", d_t_ms, None, None
    return "unknown", d_t_ms, None, None


def udp_exchange(ip, port, payload, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.send(payload)
            data = sock.recv(4096)
            return "response", data, None

    except socket.timeout:
        return "timeout", None, None
    except OSError as e:
        if (
            isinstance(e, ConnectionRefusedError)
            or e.errno in (errno.ECONNREFUSED, errno.ECONNRESET)
            or getattr(e, "winerror", None) == 10054
        ):
            return "closed", None, None
        return "error", None, str(e)


def scan_UDP(ip, port, timeout=2, do_guess=False):
    echo_token = b"portscan-echo-" + os.urandom(16)
    state, data, error = udp_exchange(ip, port, echo_token, timeout)

    if state == "error":
        return "error", None, None, error
    if state == "closed":
        return "closed", None, None, None
    is_open = state == "response"
    app_protocol = (
        "ECHO"
        if do_guess and data == echo_token
        else None
    )

    if do_guess and app_protocol is None:
        transaction_id, query = make_dns_query()
        dns_state, dns_data, dns_error = udp_exchange(ip, port, query, timeout)

        if dns_state == "response":
            is_open = True
            if is_dns_response(dns_data, transaction_id):
                app_protocol = "DNS"
        elif not is_open and dns_state == "closed":
            return "closed", None, None, None
        elif not is_open and dns_state == "error":
            return "error", None, None, dns_error
    if is_open:
        return "open", None, app_protocol, None
    return "unknown", None, None, None


def parse_targets(target_specs):
    selected = set()

    for target in target_specs:
        if "/" in target:
            protocol, port_spec = target.split("/", 1)
        else:
            protocol, port_spec = target, ""

        protocol = protocol.lower()
        if protocol not in ("tcp", "udp"):
            raise ValueError(
                f"неизвестный протокол в аргументе {target!r}; "
                "ожидается tcp или udp"
            )

        if not port_spec:
            ranges = [(1, 65535)]
        else:
            ranges = []
            for part in port_spec.split(","):
                part = part.strip()
                if not part:
                    raise ValueError(f"пустой порт в аргументе {target!r}")

                bounds = part.split("-")
                if len(bounds) == 1:
                    if not bounds[0].isascii() or not bounds[0].isdigit():
                        raise ValueError(f"неверный порт: {part!r}")
                    start = end = int(bounds[0])

                elif len(bounds) == 2:
                    if (not bounds[0].isascii()
                        or not bounds[0].isdigit()
                        or not bounds[1].isascii()
                        or not bounds[1].isdigit()
                    ):
                        raise ValueError(f"неверный диапазон портов: {part!r}")

                    start, end = int(bounds[0]), int(bounds[1])
                    if start > end:
                        raise ValueError(
                            f"начало диапазона больше конца: {part!r}"
                        )

                else:
                    raise ValueError(f"неверный диапазон портов: {part!r}")

                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError(
                        f"порт должен быть в диапазоне 1–{65535}: {part!r}"
                    )
                ranges.append((start, end))

        for start, end in ranges:
            for port in range(start, end + 1):
                selected.add((protocol, port))
    protocol_order = {"tcp": 0, "udp": 1}
    return sorted(selected, key=lambda item: (protocol_order[item[0]], item[1]))


def scan(ip, protocol, port, timeout, do_guess):
    if protocol == "tcp":
        state, d_t_ms, app_protocol, error = scan_TCP(ip, port, timeout, do_guess)
    else:
        state, d_t_ms, app_protocol, error = scan_UDP(ip, port, timeout, do_guess)

    return (
        protocol.upper(),
        port,
        state,
        d_t_ms,
        app_protocol,
        error,
    )


def main():
    parser = argparse.ArgumentParser(prog="portscan")

    parser.add_argument("--timeout", type=float, default=2.0,
                        help="таймаут ожидания ответа (по умолчанию 2с)")
    parser.add_argument("-j", "--num-threads", type=int, default=1,
                        help="число потоков")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="подробный режим")
    parser.add_argument("-g", "--guess", action="store_true",
                        help="определение протокола прикладного уровня")

    parser.add_argument("ip_address", metavar="IP_ADDRESS")
    parser.add_argument("targets", nargs="*", metavar="PROTO[/PORTS]")

    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout должен быть больше нуля")
    if args.num_threads < 1:
        parser.error("--num-threads должен быть не меньше 1")
    if not args.targets:
        parser.error("укажите tcp[/PORTS] и/или udp[/PORTS]")

    try:
        target_ip = str(ipaddress.IPv4Address(args.ip_address))
        tasks = parse_targets(args.targets)
    except ValueError as exc:
        parser.error(str(exc))

    open_ports = []
    errors = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.num_threads) as executor:
        futures = [
            executor.submit(
                scan,
                target_ip,
                protocol,
                port,
                args.timeout,
                args.guess)
            for protocol, port in tasks
        ]

        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:
                errors.add(str(exc))
                continue

            protocol, port, state, d_t_ms, app_protocol, error = result

            if state == "open":
                open_ports.append((protocol, port, d_t_ms, app_protocol))
            if error:
                errors.add(error)

    open_ports.sort(key=lambda item: (item[0] != "TCP", item[1]))

    for protocol, port, d_t_ms, app_protocol in open_ports:
        columns = [protocol, str(port)]
        if args.verbose and protocol == "TCP":
            columns.append(f"{d_t_ms:.2f}")
        if args.guess:
            columns.append(app_protocol or "-")
        print(" ".join(columns))

    for error in sorted(errors):
        print(f"portscan: {error}", file=sys.stderr)


if __name__ == "__main__":
    main()
