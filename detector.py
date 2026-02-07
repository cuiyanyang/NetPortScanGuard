import threading
import time
from scapy.all import sniff, IP, TCP
from datetime import datetime

class Detector:
    def __init__(self):
        self.running = False
        self.thread = None
        self.callback = None  # 用于界面更新的回调函数
        # 扫描统计相关属性（基于频率）
        self.scan_stats = {}  # 格式: {src_ip: {"packets": [(timestamp, dport), ...], "first_seen": timestamp}}
        self.time_window = 10  # 时间窗口大小(秒)
        self.frequency_threshold = 30  # 频率阈值：时间窗口内超过此数据包数判定为扫描行为

    def detect_scan(self, logger, gui_callback=None):
        """启动扫描检测"""
        self.running = True
        self.callback = gui_callback
        self.thread = threading.Thread(target=self._sniff_packets, args=(logger,), daemon=True)
        self.thread.start()

    def pause(self):
        """暂停检测"""
        self.running = False

    def resume(self, logger):
        """恢复检测"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._sniff_packets, args=(logger,), daemon=True)
            self.thread.start()

    def stop(self):
        """停止检测"""
        self.running = False

    def _sniff_packets(self, logger):
        """实际抓包过程"""
        def process_packet(packet):
            if not self.running:
                return False  # 中断 sniff

            if packet.haslayer(IP) and packet.haslayer(TCP):
                src = packet[IP].src
                dst = packet[IP].dst
                dport = packet[TCP].dport
                flags = packet[TCP].flags

                # 更新扫描统计
                current_time = time.time()
                if src not in self.scan_stats:
                    self.scan_stats[src] = {"packets": [], "first_seen": current_time}
                
                # 添加当前数据包到统计
                self.scan_stats[src]["packets"].append((current_time, dport))
                
                # 清理时间窗口外的数据包
                self.scan_stats[src]["packets"] = [(ts, port) for ts, port in self.scan_stats[src]["packets"] 
                                                 if current_time - ts <= self.time_window]
                
                # 基于频率的扫描行为判断
                packet_count = len(self.scan_stats[src]["packets"])
                if packet_count > self.frequency_threshold:
                    log_msg = f"[!] 检测到疑似端口扫描：来自 {src}，在 {self.time_window} 秒内发送了 {packet_count} 个数据包"
                    logger.write_info(log_msg)

                    # 如果 GUI 注册了回调，更新界面文本
                    if self.callback:
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        self.callback(f"[{timestamp}] {log_msg}")

                # 基于标志位的扫描类型识别
                scan_type = None
                if flags == "S":
                    scan_type = "SYN"
                elif flags == "F":
                    scan_type = "FIN"
                elif flags == "SA":
                    scan_type = "SYN|ACK"
                elif flags == "R":
                    scan_type = "RST"

                if scan_type:
                    # 只记录首次检测到的特定类型扫描（在当前时间窗口内）
                    # 检查当前时间窗口内是否已经记录过相同的扫描类型和端口
                    recorded = False
                    for ts, port in self.scan_stats[src]["packets"]:
                        if port == dport and time.time() - ts <= 5:  # 5秒内只记录一次
                            recorded = True
                            break
                    
                    if not recorded:
                        log_msg = f"[!] 检测到 {scan_type} 扫描：来自 {src} → {dst}:{dport}"
                        logger.write_info(log_msg)

                        # 如果 GUI 注册了回调，更新界面文本
                        if self.callback:
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            self.callback(f"[{timestamp}] {log_msg}")

        sniff(prn=process_packet, store=False, stop_filter=lambda x: not self.running)
