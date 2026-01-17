import tkinter as tk
from tkinter import messagebox, ttk
from scanner import Scanner
from detector import Detector
from logger import Logger
import os
import threading
import time

class NetPortScanGuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NetPortScanGuard")
        self.root.geometry("600x520")
        
        # 界面 UI 样式配置
        self.bg_color = "#f5f6f7"
        self.btn_color = "#2c3e50"
        self.root.configure(bg=self.bg_color)
        
        # 初始化核心逻辑组件
        self.scanner = Scanner()
        self.detector = Detector()
        self.logger = None
        self.scanning = False

        self.main_menu()

    def clear_widgets(self):
        """清空当前窗口所有组件，并初始化居中容器"""
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # 顶部装饰线条
        tk.Frame(self.root, height=4, bg="#3498db").pack(fill="x")
        
        # 基础容器：填充整个窗口空间
        self.container = tk.Frame(self.root, bg=self.bg_color)
        self.container.pack(expand=True, fill="both")
        
        # 居中容器：利用相对坐标 (0.5, 0.5) 配合 anchor 实现绝对居中
        self.content_frame = tk.Frame(self.container, bg=self.bg_color)
        self.content_frame.place(relx=0.5, rely=0.5, anchor="center")
        return self.content_frame

    def create_label(self, text, font_size, pady=10, color="#333333"):
        """封装标准 Label，默认微软雅黑字体"""
        label = tk.Label(self.content_frame, text=text, font=("Microsoft YaHei", font_size), 
                        bg=self.bg_color, fg=color)
        label.pack(pady=pady)
        return label

    def create_button(self, text, command, width=30, pady=8):
        """封装风格统一的扁平化按钮"""
        btn = tk.Button(self.content_frame, text=text, width=width, command=command,
                        bg=self.btn_color, fg="white", font=("Microsoft YaHei", 10, "bold"),
                        relief="flat", activebackground="#34495e", activeforeground="white",
                        cursor="hand2")
        btn.pack(pady=pady)
        return btn

    # --- 1. 入口主菜单 ---
    def main_menu(self):
        self.clear_widgets()
        self.create_label("=== NetPortScanGuard 系统主界面 ===", 16, pady=30)
        self.create_button("探测存活主机", self.scan_hosts)
        self.create_button("扫描检测监控", self.start_detection)
        self.create_button("查看分析日志", self.view_logs)
        self.create_button("退出安全系统", self.root.quit)

    # --- 2. 存活主机扫描模块 ---
    def scan_hosts(self):
        self.logger = Logger("scan")
        self.clear_widgets()
        
        self.create_label("正在扫描当前网段存活主机...", 12)
        
        # 进度展示组件
        progress_var = tk.DoubleVar()
        self.pb = ttk.Progressbar(self.content_frame, variable=progress_var, maximum=100, length=400)
        self.pb.pack(pady=20)
        
        self.loading_status = tk.Label(self.content_frame, text="初始化网卡...", 
                                      bg=self.bg_color, font=("Microsoft YaHei", 10))
        self.loading_status.pack()

        def run_survival():
            # 线程安全回调：更新进度条和状态文字
            def update_ui(current, total):
                percent = (current / total) * 100
                self.root.after(0, lambda: progress_var.set(percent))
                self.root.after(0, lambda: self.loading_status.config(text=f"已探测 IP: {current}/{total}"))

            # 执行 ARP 扫描，完成后切换到列表展示页
            alive_hosts = self.scanner.survival_host(progress_callback=update_ui)
            self.root.after(0, lambda: self.render_host_list(alive_hosts))

        # 启动后台线程执行扫描，防止 UI 假死
        threading.Thread(target=run_survival, daemon=True).start()

    # --- 3. 结果列表模块 ---
    def render_host_list(self, alive_hosts):
        self.clear_widgets()
        
        if not alive_hosts:
            self.create_label("未发现存活主机", 12, color="red")
            self.create_button("返回主菜单", self.close_log_and_return)
            return

        self.create_label("=== 发现以下存活主机 ===", 12, pady=10)
        
        # 列表及滚动条容器
        list_frame = tk.Frame(self.content_frame, bg=self.bg_color)
        list_frame.pack(pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        listbox = tk.Listbox(list_frame, width=60, height=10, font=("Consolas", 10),
                             yscrollcommand=scrollbar.set, borderwidth=1, relief="solid")
        for idx, (ip, mac) in enumerate(alive_hosts, 1):
            listbox.insert(tk.END, f" {idx:02d}. IP: {ip.ljust(15)}  MAC: {mac}")
        listbox.pack(side="left")
        scrollbar.config(command=listbox.yview)

        def on_select():
            selection = listbox.curselection()
            if selection:
                target_ip = alive_hosts[selection[0]][0]
                self.select_scan_mode(target_ip)

        self.create_button("选择该主机进行端口扫描", on_select)
        self.create_button("返回主菜单", self.close_log_and_return)

    # --- 4. 深度扫描配置与控制 ---
    def select_scan_mode(self, target_ip):
        self.clear_widgets()
        self.create_label(f"目标IP: {target_ip}", 12, color="#e67e22")
        self.create_label("请选择扫描技术方式", 10, pady=0)

        # 扫描技术选项映射
        mode = tk.StringVar(value="1")
        modes = {"1": "TCP Connect", "2": "TCP SYN", "3": "TCP SYN|ACK", "4": "TCP FIN", 
                 "5": "UDP 扫描", "6": "NULL 扫描", "7": "Xmas 扫描"}

        mode_frame = tk.Frame(self.content_frame, bg=self.bg_color)
        mode_frame.pack(pady=10)
        for val, name in modes.items():
            tk.Radiobutton(mode_frame, text=name, variable=mode, value=val, 
                          bg=self.bg_color, font=("Microsoft YaHei", 9)).pack(anchor="w")

        self.status_label = tk.Label(self.content_frame, text="准备就绪", bg=self.bg_color)
        self.status_label.pack()

        progress = tk.DoubleVar()
        progressbar = ttk.Progressbar(self.content_frame, variable=progress, maximum=100, length=400)
        progressbar.pack(pady=10)

        def run_scan():
            ports = list(range(20, 1025)) # 扫描范围：常用端口
            open_results = []
            self.scanning = True

            for i, port in enumerate(ports, 1):
                if not self.scanning: break
                # 通过 after 提交 UI 任务，避免非主线程直接操作 UI 组件
                self.root.after(0, lambda p=port: self.status_label.config(text=f"正在分析端口：{p}"))
                
                m = mode.get()
                res = False
                # 策略路由：根据选择调用底层不同的 Scapy 探测函数
                if m=="1": res=self.scanner.tcp_connect_scan(target_ip, port)
                elif m=="2": res=self.scanner.tcp_syn_scan(target_ip, port)
                elif m=="3": res=self.scanner.tcp_synack_scan(target_ip, port)
                elif m=="4": res=self.scanner.tcp_fin_scan(target_ip, port)
                elif m=="5": res=self.scanner.udp_scan(target_ip, port)
                elif m=="6": res=self.scanner.null_scan(target_ip, port)
                elif m=="7": res=self.scanner.xmas_scan(target_ip, port)

                if res:
                    service = self.scanner.get_service_name(target_ip, port)
                    open_results.append((port, service))
                    self.logger.write_open_port(target_ip, port)

                self.root.after(0, lambda v=i*100/len(ports): progress.set(v))

            self.scanning = False
            result_str = "\n".join([f"{p}: {s}" for p, s in open_results]) if open_results else "未发现开放端口"
            messagebox.showinfo("扫描完成", f"结果如下：\n{result_str}")
            self.root.after(0, self.close_log_and_return)

        self.create_button("开始探测", lambda: threading.Thread(target=run_scan, daemon=True).start())
        self.create_button("取消并返回", self.close_log_and_return)

    # --- 5. 入侵检测/抓包监控 ---
    def start_detection(self):
        self.clear_widgets()
        self.logger = Logger("detect")
        self.create_label("网络异常扫描实时监控", 14)
        
        self.alert_status = tk.Label(self.content_frame, text="● 系统监听中 - 状态安全", fg="green", bg=self.bg_color)
        self.alert_status.pack()

        self.output_box = tk.Text(self.content_frame, width=70, height=15, state='disabled', font=("Consolas", 9))
        self.output_box.pack(pady=10)

        # 接收 detector 传回的抓包分析信息
        def gui_callback(msg):
            def update():
                self.output_box.configure(state='normal')
                self.output_box.insert(tk.END, msg + '\n')
                self.output_box.see(tk.END) # 自动滚动到底部
                self.output_box.configure(state='disabled')
                if "攻击" in msg or "!" in msg:
                    self.alert_status.config(text="▲ 警告：检测到异常行为！", fg="red")
            self.root.after(0, update)

        self.detector.detect_scan(self.logger, gui_callback)
        self.create_button("停止监控并返回", self.close_log_and_return)

    # --- 6. 历史记录查询 ---
    def view_logs(self):
        self.clear_widgets()
        log_dir = "log"
        if not os.path.exists(log_dir): os.makedirs(log_dir)
        # 获取最近 10 条日志，逆序排列（最新在前）
        files = sorted([f for f in os.listdir(log_dir) if f.endswith(".log")], reverse=True)[:10]

        self.create_label("最近 10 条安全日志", 12)
        listbox = tk.Listbox(self.content_frame, width=60, height=10)
        for f in files: listbox.insert(tk.END, f)
        listbox.pack(pady=10)

        def read_log():
            selection = listbox.curselection()
            if selection:
                with open(os.path.join(log_dir, files[selection[0]]), "r", encoding="utf-8") as f:
                    content = f.read()
                log_win = tk.Toplevel(self.root) # 弹出独立窗口显示日志
                log_win.title("日志详情")
                t = tk.Text(log_win, width=80, height=20)
                t.insert(tk.END, content)
                t.pack()

        self.create_button("阅读选中的日志", read_log)
        self.create_button("返回主菜单", self.main_menu)

    def close_log_and_return(self):
        """通用资源回收与状态重置"""
        self.scanning = False
        if self.logger:
            self.logger.close()
            self.logger = None
        self.detector.stop() # 释放 Scapy 嗅探线程
        self.main_menu()

def start_gui():
    root = tk.Tk()
    # 窗口居中计算逻辑
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"600x520+{(sw-600)//2}+{(sh-520)//2}")
    app = NetPortScanGuardGUI(root)
    root.mainloop()

if __name__ == "__main__":
    start_gui()