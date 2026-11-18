import argparse


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


if __name__ == "__main__":
    main()
