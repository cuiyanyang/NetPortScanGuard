import threading
import time
from scapy.all import sniff, IP, TCP
from datetime import datetime

class Detector:
    def __init__(self):
        self.running = False
        self.thread = None
        self.callback = None  # 用于界面更新的回调函数

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
                    log_msg = f"[!] 检测到 {scan_type} 扫描：来自 {src} → {dst}:{dport}"
                    logger.write_info(log_msg)

                    # 如果 GUI 注册了回调，更新界面文本
                    if self.callback:
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        self.callback(f"[{timestamp}] {log_msg}")

        sniff(prn=process_packet, store=False, stop_filter=lambda x: not self.running)
