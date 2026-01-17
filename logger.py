import os
import time
from datetime import datetime

class Logger:
    def __init__(self, operation):
        """
        创建日志文件，命名为：日期-时间-操作类型.log，例如：20250516-153010-scan.log
        """
        self.operation = operation
        self.log_dir = "log"
        os.makedirs(self.log_dir, exist_ok=True)

        # 创建时间戳和文件名
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.start_time = time.time()
        self.log_filename = f"{timestamp}-{operation}.log"
        self.log_path = os.path.join(self.log_dir, self.log_filename)

        # 写入开始信息
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"[START] {datetime.now()} - 操作类型: {operation}\n")

    def write_info(self, message):
        """写入带时间戳的普通信息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")

    def write_open_port(self, ip, port):
        """专门记录端口开放信息"""
        self.write_info(f"[+] {ip}:{port} 端口开放")

    def close(self):
        """写入操作完成信息和耗时"""
        duration = time.time() - self.start_time
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"[END] {datetime.now()} - 操作完成，总耗时：{duration:.2f} 秒\n")
