## pyNmap
```
基于 Scapy 实现的仿 nmap SYN 扫描器
```

### 一、需求
```
1、基于 Scapy 实现
2、利用 SYN 扫描开放端口
3、支持 1-65535 全端口扫描
4、结果采用类似 nmap 的方式展示
```
###### [注] nmap的扫描结果
```
┌──(root㉿kali)-[/home/kali]
└─# nmap -v -sS 192.168.20.1
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-27 20:58 EDT
Initiating ARP Ping Scan at 20:58
Scanning 192.168.20.1 [1 port]
Completed ARP Ping Scan at 20:58, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:58
Completed Parallel DNS resolution of 1 host. at 20:58, 0.01s elapsed
Initiating SYN Stealth Scan at 20:58
Scanning 192.168.20.1 [1000 ports]
Discovered open port 445/tcp on 192.168.20.1
Discovered open port 443/tcp on 192.168.20.1
Discovered open port 139/tcp on 192.168.20.1
Discovered open port 135/tcp on 192.168.20.1
Discovered open port 10001/tcp on 192.168.20.1
Discovered open port 912/tcp on 192.168.20.1
Discovered open port 8000/tcp on 192.168.20.1
Discovered open port 7000/tcp on 192.168.20.1
Discovered open port 902/tcp on 192.168.20.1
Completed SYN Stealth Scan at 20:58, 1.29s elapsed (1000 total ports)
Nmap scan report for 192.168.20.1
Host is up (0.0010s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
902/tcp   open  iss-realsecure
912/tcp   open  apex-mesh
7000/tcp  open  afs3-fileserver
8000/tcp  open  http-alt
10001/tcp open  scp-config
MAC Address: 00:50:56:C0:00:08 (VMware)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.48 seconds
           Raw packets sent: 1082 (47.592KB) | Rcvd: 1001 (40.064KB)
```

### 二、分步实现

#### 1、帮助文档，采用@click的形式显示命令行的操作方法
```python
@click.command()
@click.option("--verbose", help="Verbose or not (default False)", type=bool, required=False, default=False)
@click.option("--port", help="Port ranges(default: 1-65535)", default="1-65535")
@click.option("--ping", help="Ping before scan", default=False)
@click.option("--timeout", help="Time you want to wait after the last packet been sent", default=3.0)
@click.argument("dst", required=True, type=str) # required, not optional
```

#### 2、扫描函数，用于实现syn的scan
```python
def scan(dst, ports, timeout, verbose=False):
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
```

#### 3、主函数
```python
def scan(dst, ports, timeout, verbose=False):
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
```

### 三、演示
#### 1、查看帮助和命令行操作
```
(venv) [root@localhost pycharm]# python3 main.py --help
Usage: main.py [OPTIONS] DST

  A simple SYN scan

Options:
  --verbose BOOLEAN  Verbose or not (default False)
  --port TEXT        Port ranges(default: 1-65535)
  --ping BOOLEAN     Ping before scan
  --timeout FLOAT    Time you want to wait after the last packet been sent
  --help             Show this message and exit.

```

#### 2、扫描端口
```
(venv) [root@localhost pycharm]# python3 main.py --verbose True --port 1-1005 192.168.20.1
Starting pyNmap 1.0... at Sun Mar 27 21:15:09 2022
Scanning 192.168.20.1[1005 ports] at Sun Mar 27 21:15:09 2022
Discovered open port 135/tcp on 192.168.20.1
Discovered open port 139/tcp on 192.168.20.1
Discovered open port 443/tcp on 192.168.20.1
Discovered open port 445/tcp on 192.168.20.1
Discovered open port 902/tcp on 192.168.20.1
Discovered open port 912/tcp on 192.168.20.1
Completed SYN Stealth Scan, 5s elapsed (1005 total ports) at Sun Mar 27 21:15:14 2022
pyNmap scan report for 192.168.20.1
Not shown: 999 filtered ports
PORT            STATE           SERVICE
135/tcp         open            msrpc
139/tcp         open            msf
443/tcp         open            https
445/tcp         open            msf
902/tcp         open            UNKNOWN
912/tcp         open            UNKNOWN
pyNmap done: 1 IP address(up) scanned in 5 seconds
```

### 四、改进
#### 1、实现多线程
#### 2、对于其他扫描方式进行判断
