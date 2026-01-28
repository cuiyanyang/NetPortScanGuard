import socket
from scapy.all import ARP, Ether, srp, IP, TCP, UDP, sr1, get_if_list, get_if_addr, conf
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

class Scanner:
    def __init__(self):
        # 默认服务映射表，用于 Banner 抓取失败时的辅助识别
        self.common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
            8080: "HTTP-Proxy", 27017: "MongoDB"
        }

    def get_local_ip(self):
        """利用 socket 接口获取当前主机的内网 IP 地址"""
        hostname = socket.gethostname()
        ip_add = socket.gethostbyname(hostname)
        return ip_add

    def set_interface_by_ip(self, local_ip):
        """根据 IP 段匹配结果自动切换 Scapy 工作网卡，确保发包链路正确"""
        ip_prefix = ".".join(local_ip.split(".")[:3]) + "."
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip.startswith(ip_prefix):
                    conf.iface = iface # 绑定 Scapy 核心发包接口
                    return True
            except Exception:
                continue
        return False

    def survival_host(self, progress_callback=None):
        """执行 ARP 广播探测，并发扫描 /24 网段内存活的二层节点"""
        local_ip = self.get_local_ip()
        if not self.set_interface_by_ip(local_ip):
            return []

        # 动态计算子网范围（基于当前 IP 生成 1-254 地址池）
        ip_parts = local_ip.split(".")
        network_prefix = ".".join(ip_parts[:3]) + ".0/24"
        hosts_to_scan = [str(ip) for ip in ipaddress.IPv4Network(network_prefix).hosts()]
        alive_hosts = []
        total = len(hosts_to_scan)
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            future_to_ip = {executor.submit(self._arp_single_host, ip): ip for ip in hosts_to_scan}
            for i, future in enumerate(as_completed(future_to_ip), 1):
                result = future.result()
                if result:
                    alive_hosts.append(result)
                # 实时向 GUI 层推送异步扫描进度
                if progress_callback:
                    progress_callback(i, total)

        # 结果按 IP 升序重排，便于前端列表渲染
        return sorted(alive_hosts, key=lambda x: ipaddress.IPv4Address(x[0]))

    def _arp_single_host(self, target_ip):
        """构造并发送单条 ARP Request，获取目标 MAC 地址"""
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff") # 全网段广播
        packet = ether / arp
        try:
            result = srp(packet, timeout=1, verbose=0)[0]
            if result:
                # 返回发现的 IP 和 硬件地址
                return (result[0][1].psrc, result[0][1].hwsrc)
        except: pass
        return None

    # --- 协议指纹与 Banner 识别 ---

    def get_service_name(self, ip, port):
        """应用层服务识别：优先通过 Banner Grab 抓取原始指纹信息"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                s.connect((ip, port))
                # 尝试读取目标服务的欢迎报文（如 SSH-2.0... 或 FTP 220...）
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    return f"{self.common_services.get(port, 'Unknown')} ({banner[:20]})"
        except:
            pass
        
        # 指纹抓取失败时，通过端口号回退到静态映射查找
        return self.common_services.get(port, "Unknown Service")

    # --- 扫描算法底层实现 (TCP/UDP/Raw IP) ---

    def tcp_connect_scan(self, ip, port):
        """TCP 全连接扫描：完成三次握手过程，结果最可靠但隐蔽性差"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port)) # 连接成功返回 0
            sock.close()
            return result == 0
        except: return False

    def tcp_syn_scan(self, ip, port):
        """SYN 半连接扫描：发送 S 包，根据是否返回 SA (0x12) 判断端口状态"""
        try:
            res = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
            return res and res.haslayer(TCP) and res[TCP].flags == 0x12 
        except: return False

    def tcp_synack_scan(self, ip, port):
        """SYN|ACK 扫描：反向探测，若收到 RST (0x14) 响应则证明路径可达且端口开启"""
        try:
            res = sr1(IP(dst=ip)/TCP(dport=port, flags="SA"), timeout=1, verbose=0)
            return res and res.haslayer(TCP) and res[TCP].flags == 0x14 
        except: return False

    def tcp_fin_scan(self, ip, port):
        """FIN 扫描：利用 RFC 793 特性，若开放端口对 F 包无响应则判定为 Open/Filtered"""
        try:
            res = sr1(IP(dst=ip)/TCP(dport=port, flags="F"), timeout=1, verbose=0)
            return res is None 
        except: return False

    def udp_scan(self, ip, port):
        """UDP 扫描：基于无连接协议。无响应或返回 UDP 报文均视为可能开放"""
        try:
            res = sr1(IP(dst=ip)/UDP(dport=port), timeout=2, verbose=0)
            if res is None: 
                return True
            elif res.haslayer(UDP):
                return True
            return False
        except: return False

    def null_scan(self, ip, port):
        """NULL 扫描：发送 Flag 全空的 TCP 包。无响应通常表示端口处于监听状态"""
        try:
            res = sr1(IP(dst=ip)/TCP(dport=port, flags=""), timeout=1, verbose=0)
            return res is None
        except: return False

    def xmas_scan(self, ip, port):
        """圣诞树扫描：同时置位 F/U/P 指示位。若目标符合 RFC 规范且无响应，则视为开放"""
        try:
            res = sr1(IP(dst=ip)/TCP(dport=port, flags="FUP"), timeout=1, verbose=0)
            return res is None
        except: return False