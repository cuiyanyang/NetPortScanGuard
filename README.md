# 安装依赖库 
```pip install -r requirements.txt```

# 连接数据库
修改```logger.py```文件第6-10行中的mysql```user```和```password```以连接到数据库
```
DEFAULT_MYSQL_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'mysql',
    'database': 'port_log_db'
}
```

# 运行程序
```python .\main.py```