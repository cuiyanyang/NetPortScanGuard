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
        self.root.geometry("750x650")
        
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

    def create_button(self, text, command, width=40, pady=12):
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
        self.create_label("=== NetPortScanGuard 系统主界面 ===", 16, pady=40)
        self.create_button("端口扫描", self.scan_hosts)
        self.create_button("扫描检测", self.start_detection)
        self.create_button("查看日志", self.view_logs)
        self.create_button("退出系统", self.root.quit)

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
        
        listbox = tk.Listbox(list_frame, width=70, height=12, font=("Consolas", 10),
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
        
        mode_frame = tk.Frame(self.content_frame, bg=self.bg_color)
        mode_frame.pack(pady=10)
        
        # 创建2x2网格布局
        grid_frame = tk.Frame(mode_frame, bg=self.bg_color)
        grid_frame.pack()
        
        # 第一行第一个：TCP 基础扫描
        frame1 = tk.Frame(grid_frame, bg=self.bg_color, padx=20, pady=10)
        frame1.grid(row=0, column=0, sticky="nw")
        tk.Label(frame1, text="● TCP 基础扫描", font=("Microsoft YaHei", 10, "bold"), bg=self.bg_color).pack(anchor="w", pady=(0, 5))
        tk.Radiobutton(frame1, text="TCP 全连接扫描", variable=mode, value="1", 
                      bg=self.bg_color, font=("Microsoft YaHei", 9)).pack(anchor="w", padx=10)
        
        # 第一行第二个：TCP 标志位扫描
        frame2 = tk.Frame(grid_frame, bg=self.bg_color, padx=20, pady=10)
        frame2.grid(row=0, column=1, sticky="nw")
        tk.Label(frame2, text="● TCP 标志位扫描", font=("Microsoft YaHei", 10, "bold"), bg=self.bg_color).pack(anchor="w", pady=(0, 5))
        tk.Radiobutton(frame2, text="TCP SYN 扫描", variable=mode, value="2", 
                      bg=self.bg_color, font=("Microsoft YaHei", 9)).pack(anchor="w", padx=10)
        tk.Radiobutton(frame2, text="TCP SYN|ACK 扫描", variable=mode, value="3", 
                      bg=self.bg_color, font=("Microsoft YaHei", 9)).pack(anchor="w", padx=10)
        
        # 第二行第一个：TCP 隐蔽扫描
        frame3 = tk.Frame(grid_frame, bg=self.bg_color, padx=20, pady=10)
        frame3.grid(row=1, column=0, sticky="nw")
        tk.Label(frame3, text="● TCP 隐蔽扫描", font=("Microsoft YaHei", 10, "bold"), bg=self.bg_color).pack(anchor="w", pady=(0, 5))
        tk.Radiobutton(frame3, text="TCP FIN 扫描", variable=mode, value="4", 
                      bg=self.bg_color, font=("Microsoft YaHei", 9)).pack(anchor="w", padx=10)
        tk.Radiobutton(frame3, text="NULL 扫描", variable=mode, value="6", 
                      bg=self.bg_color, font=("Microsoft YaHei", 9)).pack(anchor="w", padx=10)
        tk.Radiobutton(frame3, text="Xmas 扫描", variable=mode, value="7", 
                      bg=self.bg_color, font=("Microsoft YaHei", 9)).pack(anchor="w", padx=10)
        
        # 第二行第二个：UDP 扫描
        frame4 = tk.Frame(grid_frame, bg=self.bg_color, padx=20, pady=10)
        frame4.grid(row=1, column=1, sticky="nw")
        tk.Label(frame4, text="● UDP 扫描", font=("Microsoft YaHei", 10, "bold"), bg=self.bg_color).pack(anchor="w", pady=(0, 5))
        tk.Radiobutton(frame4, text="UDP 扫描", variable=mode, value="5", 
                      bg=self.bg_color, font=("Microsoft YaHei", 9)).pack(anchor="w", padx=10)

        self.status_label = tk.Label(self.content_frame, text="准备就绪", bg=self.bg_color, font=("Microsoft YaHei", 10))
        self.status_label.pack(pady=8)

        progress = tk.DoubleVar()
        progressbar = ttk.Progressbar(self.content_frame, variable=progress, maximum=100, length=500)
        progressbar.pack(pady=15)

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
            self.root.after(0, lambda: self.status_label.config(text="扫描完成"))
        self.create_button("开始探测", lambda: threading.Thread(target=run_scan, daemon=True).start())
        self.create_button("取消", lambda: setattr(self, "scanning", False))
        self.create_button("返回主菜单", self.close_log_and_return)

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
        self.create_label("所有安全日志", 12)
        
        # 从MySQL数据库读取所有表
        try:
            import pymysql
            
            # 连接MySQL数据库
            connection = pymysql.connect(
                host='localhost',
                user='root',
                password='mysql',
                database='port_log_db',
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            
            # 获取所有扫描和检测相关的表
            with connection.cursor() as cursor:
                # 分别查询两种类型的表并合并结果
                cursor.execute("SHOW TABLES LIKE '%-scan'")
                scan_tables = cursor.fetchall()
                cursor.execute("SHOW TABLES LIKE '%-detect'")
                detect_tables = cursor.fetchall()
                tables = scan_tables + detect_tables
            
            # 提取表名并按时间倒序排序
            table_names = []
            for table in tables:
                # 不同MySQL版本返回格式可能不同
                if 'Tables_in_port_log_db' in table:
                    table_names.append(table['Tables_in_port_log_db'])
                else:
                    for key, value in table.items():
                        table_names.append(value)
            
            # 按表名排序（时间戳顺序）
            table_names.sort(reverse=True)
            
            connection.close()
            
            if not table_names:
                self.create_label("暂无日志记录", 12, color="red")
                self.create_button("返回主菜单", self.main_menu)
                return
            
            # 创建表列表
            self.create_label("请选择要查看的操作记录", 10, pady=5)
            table_listbox = tk.Listbox(self.content_frame, width=60, height=10)
            for table in table_names:
                # 解析表名，提取时间和操作类型
                table_listbox.insert(tk.END, table)
            table_listbox.pack(pady=10)
            
            # 查看选中表的内容
            def view_selected_table():
                selection = table_listbox.curselection()
                if selection:
                    selected_table = table_names[selection[0]]
                    self.view_table_content(selected_table)
            
            # 删除选中的表
            def delete_selected_table():
                selection = table_listbox.curselection()
                if selection:
                    selected_table = table_names[selection[0]]
                    if messagebox.askyesno("确认删除", f"确定要删除表 {selected_table} 吗？此操作不可恢复！"):
                        try:
                            connection = pymysql.connect(
                                host='localhost',
                                user='root',
                                password='mysql',
                                database='port_log_db',
                                charset='utf8mb4',
                                cursorclass=pymysql.cursors.DictCursor
                            )
                            
                            with connection.cursor() as cursor:
                                sql = f"DROP TABLE IF EXISTS `{selected_table}`"
                                cursor.execute(sql)
                                connection.commit()
                            
                            connection.close()
                            messagebox.showinfo("删除成功", f"表 {selected_table} 已成功删除")
                            # 重新加载表列表
                            self.view_logs()
                        except Exception as e:
                            messagebox.showerror("删除失败", f"删除表时出错: {str(e)}")
            
            self.create_button("查看选中的操作记录", view_selected_table)
            self.create_button("删除选中的操作记录", delete_selected_table)
            self.create_button("返回主菜单", self.main_menu)
            
        except Exception as e:
            self.create_label(f"加载日志失败: {str(e)}", 10, color="red")
            self.create_button("返回主菜单", self.main_menu)
    
    def view_table_content(self, table_name):
        """查看指定表的内容"""
        self.clear_widgets()
        self.create_label(f"操作记录: {table_name}", 12)
        
        try:
            import pymysql
            
            # 连接MySQL数据库
            connection = pymysql.connect(
                host='localhost',
                user='root',
                password='mysql',
                database='port_log_db',
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            
            # 查询表内容
            with connection.cursor() as cursor:
                sql = f"SELECT id, time, type, info FROM `{table_name}` ORDER BY time ASC"
                cursor.execute(sql)
                logs = cursor.fetchall()
            
            connection.close()
            
            # 创建日志列表
            listbox = tk.Listbox(self.content_frame, width=80, height=12)
            for log in logs:
                # 格式化日志显示
                timestamp = log['time'].strftime('%Y-%m-%d %H:%M:%S')
                item = f"[{timestamp}] [{log['type']}] {log['info']}"
                listbox.insert(tk.END, item)
            listbox.pack(pady=10)
            
            def read_log():
                selection = listbox.curselection()
                if selection:
                    log = logs[selection[0]]
                    # 格式化日志详情
                    timestamp = log['time'].strftime('%Y-%m-%d %H:%M:%S')
                    content = f"时间: {timestamp}\n"
                    content += f"类型: {log['type']}\n"
                    content += f"信息: {log['info']}\n"
                    
                    log_win = tk.Toplevel(self.root)
                    log_win.title("日志详情")
                    log_win.geometry("800x300")
                    t = tk.Text(log_win)
                    t.insert(tk.END, content)
                    t.pack(fill=tk.BOTH, expand=True)
            
            self.create_button("阅读选中的日志", read_log)
            self.create_button("返回日志列表", self.view_logs)
            self.create_button("返回主菜单", self.main_menu)
            
        except Exception as e:
            self.create_label(f"加载日志失败: {str(e)}", 10, color="red")
            self.create_button("返回日志列表", self.view_logs)
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