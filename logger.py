import time
from datetime import datetime
import pymysql

# 默认MySQL配置
DEFAULT_MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'mysql',
    'database': 'port_log_db'
}

class Logger:
    def __init__(self, operation, mysql_config=None):
        """
        初始化日志记录器，仅连接MySQL数据库存储日志
        
        Args:
            operation: 操作类型
            mysql_config: MySQL连接配置字典，包含host, user, password, database等
                        如果不提供，将使用默认配置
        """
        self.operation = operation
        self.start_time = time.time()
        
        # 生成动态表名
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.table_name = f"{timestamp}-{operation}"

        # 初始化MySQL连接
        self.db_connection = None
        self.db_cursor = None
        self._init_mysql(mysql_config)

    def _init_mysql(self, mysql_config):
        """初始化MySQL连接并创建表"""
        try:
            # 使用默认配置或传入的配置
            config = DEFAULT_MYSQL_CONFIG.copy()
            if mysql_config:
                config.update(mysql_config)
            
            self.db_connection = pymysql.connect(
                host=config['host'],
                user=config['user'],
                password=config['password'],
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            self.db_cursor = self.db_connection.cursor()

            # 创建数据库（如果不存在）
            create_db_sql = f"CREATE DATABASE IF NOT EXISTS {config['database']}"
            self.db_cursor.execute(create_db_sql)
            self.db_connection.commit()
            
            # 切换到指定数据库
            use_db_sql = f"USE {config['database']}"
            self.db_cursor.execute(use_db_sql)

            # 创建动态表（如果不存在）
            create_table_sql = f"""
            CREATE TABLE IF NOT EXISTS `{self.table_name}` (
                id INT AUTO_INCREMENT PRIMARY KEY,
                time DATETIME NOT NULL,
                type VARCHAR(20) NOT NULL,
                info TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
            self.db_cursor.execute(create_table_sql)
            self.db_connection.commit()

            # 记录开始信息到数据库
            start_time = datetime.now()
            insert_sql = f"""
            INSERT INTO `{self.table_name}` (time, type, info)
            VALUES (%s, %s, %s)
            """
            self.db_cursor.execute(insert_sql, (start_time, "START", f"操作类型: {self.operation}"))
            self.db_connection.commit()

        except Exception as e:
            # 数据库连接失败时，打印错误信息
            print(f"[ERROR] MySQL连接失败: {str(e)}")
            self.db_connection = None
            self.db_cursor = None

    def write_info(self, message):
        """写入带时间戳的普通信息到MySQL"""
        # 解析消息，提取类型和信息
        log_type = "INFO"
        log_info = message
        
        # 尝试从消息中提取类型
        if message.startswith("[START]"):
            log_type = "START"
            log_info = message[7:].strip()
        elif message.startswith("[END]"):
            log_type = "END"
            log_info = message[5:].strip()
        elif message.startswith("[+]"):
            log_type = "+"
            log_info = message[3:].strip()
        elif message.startswith("[!"):
            log_type = "!"
            log_info = message[3:].strip()
        
        # 写入到MySQL
        if self.db_connection and self.db_cursor:
            try:
                insert_sql = f"""
                INSERT INTO `{self.table_name}` (time, type, info)
                VALUES (%s, %s, %s)
                """
                self.db_cursor.execute(insert_sql, (datetime.now(), log_type, log_info))
                self.db_connection.commit()
            except Exception as e:
                # 数据库写入失败时，打印错误信息
                print(f"[ERROR] MySQL写入失败: {str(e)}")

    def write_open_port(self, ip, port):
        """专门记录端口开放信息到MySQL"""
        message = f"[+] {ip}:{port} 端口开放"
        self.write_info(message)

    def close(self):
        """写入操作完成信息和耗时，关闭数据库连接"""
        duration = time.time() - self.start_time
        end_message = f"[END] 操作完成，总耗时：{duration:.2f} 秒"
        
        # 写入到MySQL
        if self.db_connection and self.db_cursor:
            try:
                insert_sql = f"""
                INSERT INTO `{self.table_name}` (time, type, info)
                VALUES (%s, %s, %s)
                """
                self.db_cursor.execute(insert_sql, (datetime.now(), "END", end_message[5:].strip()))
                self.db_connection.commit()

                # 关闭数据库连接
                self.db_cursor.close()
                self.db_connection.close()
            except Exception as e:
                # 数据库写入失败时，打印错误信息
                print(f"[ERROR] MySQL关闭失败: {str(e)}")

    @staticmethod
    def get_all_log_tables():
        """获取所有日志表"""
        try:
            # 使用默认配置
            config = DEFAULT_MYSQL_CONFIG
            connection = pymysql.connect(
                host=config['host'],
                user=config['user'],
                password=config['password'],
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            
            # 切换到指定数据库
            with connection.cursor() as cursor:
                use_db_sql = f"USE {config['database']}"
                cursor.execute(use_db_sql)
            
            with connection.cursor() as cursor:
                # 分别查询两种类型的表并合并结果
                cursor.execute("SHOW TABLES LIKE '%-scan'")
                scan_tables = cursor.fetchall()
                cursor.execute("SHOW TABLES LIKE '%-detect'")
                detect_tables = cursor.fetchall()
                tables = scan_tables + detect_tables
            
            # 提取表名
            table_names = []
            for table in tables:
                if 'Tables_in_port_log_db' in table:
                    table_names.append(table['Tables_in_port_log_db'])
                else:
                    for key, value in table.items():
                        table_names.append(value)
            
            # 按表名排序（时间戳顺序）
            table_names.sort(reverse=True)
            
            connection.close()
            return table_names
        except Exception as e:
            print(f"[ERROR] 获取日志表失败: {str(e)}")
            return []

    @staticmethod
    def get_logs_from_table(table_name):
        """获取指定表的日志内容"""
        try:
            # 使用默认配置
            config = DEFAULT_MYSQL_CONFIG
            connection = pymysql.connect(
                host=config['host'],
                user=config['user'],
                password=config['password'],
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            
            # 切换到指定数据库
            with connection.cursor() as cursor:
                use_db_sql = f"USE {config['database']}"
                cursor.execute(use_db_sql)
            
            with connection.cursor() as cursor:
                sql = f"SELECT id, time, type, info FROM `{table_name}` ORDER BY time ASC"
                cursor.execute(sql)
                logs = cursor.fetchall()
            
            connection.close()
            return logs
        except Exception as e:
            print(f"[ERROR] 获取日志内容失败: {str(e)}")
            return []

    @staticmethod
    def delete_log_table(table_name):
        """删除指定的日志表"""
        try:
            # 使用默认配置
            config = DEFAULT_MYSQL_CONFIG
            connection = pymysql.connect(
                host=config['host'],
                user=config['user'],
                password=config['password'],
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            
            # 切换到指定数据库
            with connection.cursor() as cursor:
                use_db_sql = f"USE {config['database']}"
                cursor.execute(use_db_sql)
            
            with connection.cursor() as cursor:
                sql = f"DROP TABLE IF EXISTS `{table_name}`"
                cursor.execute(sql)
                connection.commit()
            
            connection.close()
            return True
        except Exception as e:
            print(f"[ERROR] 删除日志表失败: {str(e)}")
            return False
