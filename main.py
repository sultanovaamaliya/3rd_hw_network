import argparse
import random
import socket
import time

from scapy.all import IP, TCP, ICMP, sr1, send

# Примеры указания диапазона портов:
# portscan 1.1.1.1 tcp/80 tcp/12000-12500 udp/3000-3100,3200,3300-4000
# portscan 1.1.1.1 tcp udp/40000
# ```
#
# В ответ утилита должна выдавать список открытых портов согласно переданному списку в формате:
# ```
# TCP|UDP PORT [TIME,ms] [PROTOCOL|-]

# TCP-заголовок на проводе имеет фиксированный порядок:
#
# порт отправителя | порт получателя
# номер последовательности (seq)
# номер подтверждения (ack)
# длина заголовка и флаги
# окно | контрольная сумма | срочный указатель


def scan_TCP(ip, port, timeout=2):
    source_port = random.randrange(49152, 65536)
    source_seq = random.getrandbits(32)

    ip_packet = IP(dst=ip)
    tcp_packet = TCP(sport=source_port, dport=port, flags="S", seq=source_seq, )
    syn_packet = ip_packet / tcp_packet

    start = time.monotonic()

    try:
        response = sr1(syn_packet, timeout=timeout, verbose=0)
    except Exception as e:
        print(f"port: {port} ошибка {e}")

    d_t_ms = (time.monotonic() - start) * 1000
    if response is None:
        return "фильтрация/хз, потеряли", None

    if response.haslayer(ICMP):
        return "фильтрация/хз, потеряли", d_t_ms

    tcp_rep = response.getlayer(TCP)
    ip_rep = response.getlayer(IP)
    if tcp_rep is None or ip_rep is None:
        return "unknown", d_t_ms

    if tcp_rep.sport != port or tcp_rep.dport != source_port:
        return "unknown", d_t_ms

    flags = int(tcp_rep.flags)
    if (flags & 0x12) == 0x12 and (tcp_rep.ack == ((source_seq + 1) & 0xFFFFFFFF)):
        ip2_packet = IP(src=ip_rep.dst, dst=ip_rep.src)
        tsp2_packet = TCP(sport=source_port, dport=port, flags="R", seq=tcp_rep.ack)
        rst_packet = ip2_packet / tsp2_packet

        try:
            send(rst_packet, verbose=0)
        except Exception as e:
            return f"open, но не удалось отправить RST: {e}", d_t_ms
        return "open", d_t_ms

    if flags & 0x04:
        return "closed", d_t_ms
    return "unknown", d_t_ms


def scan_UDP(ip, port, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #без гарантии доставки, IPv4
    sock.settimeout(timeout)

    try:
        sock.sendto(b'test', (ip, port))
        data, address = sock.recvfrom(1024)
        print(f"port: {port} открыт")
    except socket.timeout:
        print(f"port: {port} вероятно закрыт")
    except Exception as e:
        print(f"port: {port} ошибка {e}")
    finally:
        sock.close()

state, ms = scan_TCP("127.0.0.1", 8000)
print(state, ms)

# for port in range(1, 1024):
#     scanUDP(target_ip, port)


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


# if __name__ == "__main__":
#     main()
