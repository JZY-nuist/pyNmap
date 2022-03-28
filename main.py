from scapy.all import *
import click
import time
from random import randint


m = {
    21: 'tcp',
    22: 'ssh',
    23: 'telnet',
    25: 'sstp',
    80: 'http',
    139: 'msf',
    443: 'https',
    445: 'msf',
    1433: 'mssql',
    3306: 'MySQL',
    5900: 'VNC'
}
start_info = "Starting pyNmap 1.0..."


def show_info(info):
    print(f'{info} at {time.asctime()}')


def scan_range(dst, ports, timeout, verbose=False):
    """Scan a range of ports

    Arguments:
        dst {str} --target IP address
        ports {list} --ports need to be scanned

     Keyword Arguments:
        timeout {number} -- time wait for a response packet (default: {timeout})
        verbose {bool} -- verbose or not (default: {False})
    """
    exist_port = []
    for port in ports:
        packet = IP(dst=dst) / TCP(sport=12345, dport=port, flags="S")
        # syn+ack
        response = sr1(packet, timeout=timeout, verbose=False)
        # if_exist
        if (str(type(response)) == "<class 'NoneType'>"):
            print(f'{dst} is down')
            return []
        elif (response.haslayer(TCP)):
            if (response.getlayer(TCP).flags == 0x12):
                # return ack
                # send_rst = sr(IP(dst=dst) / TCP(sport=12345, dport=port, flags="AR"))
                exist_port.append(port)
                print(f'Discovered open port {port}/tcp on {dst}')
    return exist_port


@click.command()
@click.option("--verbose", help="Verbose or not (default False)", type=bool, required=False, default=False)
@click.option("--port", help="Port ranges(default: 1-65535)", default="1-65535")
@click.option("--ping", help="Ping before scan", default=False)
@click.option("--timeout", help="Time you want to wait after the last packet been sent", default=3.0)
@click.argument("dst", required=True, type=str) # required, not optional
def pyNmap(dst, port, verbose, ping, timeout):
    """
    A simple SYN scan
    """
    start_time = time.time()
    if ping:
        ans, uans = sr(IP(dst=dst)/ICMP(id=randint(1, 65535), seq=randint(1, 65535))/b'rootkit', timeout=timeout, verbose=False, retry=2)
        if not ans:
            elasped = time.time() - start_time
            print('Host seems down.')
            print(f'pyNmap done: i IP address(0 hosts up) scanned in {round(elasped)} seconds')
            return
        else:
            for snd, rcv in ans:
                elasped = time.time() - start_time
                print(f'Get the response from {rcv.src} in {round(elasped * 1000)} ms')
                return
    if verbose:
        show_info(start_info)
    if '-' in port:
        start, end = list(map(int, port.split('-')))
        if start < 1 or end > 65535 or start > end:
            print('Invalid port range')
            return
        ports = [i for i in range(start, end+1)]
        if verbose:
            show_info(f'Scanning {dst}[{end - start + 1} ports]')

    else:
        start = end = int(port) # only one port need to scan
        ports = [start]
        if verbose:
            show_info(f'Scanning[{dst} one port]')

    exist_ports = scan_range(dst, ports, timeout=timeout, verbose=verbose)
    end_time = time.time()
    elapsed = end_time - start_time
    if verbose:
        show_info(f"Completed SYN Stealth Scan, {round(elapsed)}s elapsed ({end - start + 1} total ports)")

    print(f'pyNmap scan report for {dst}')
    print(f'Not shown: {end - start + 1 - len(exist_ports)} filtered ports')
    print('PORT\t\tSTATE\t\tSERVICE')
    for port in exist_ports:
        port_str = str(port) + "/tcp"
        open_str = "open"
        print(f"{port_str:<8s}\t{open_str:<8s}\t{m.get(port, 'UNKNOWN')}")
    print(f"pyNmap done: 1 IP address(up) scanned in {round(elapsed)} seconds")

if __name__ == "__main__":
    pyNmap()
