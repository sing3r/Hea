#  Mysql

## Mysql 基线相关配置

### 部分基线加固

通过编辑 `/etc/my.cnf` 进行配置，编辑后需要重启 Mysql 服务使配置文件生效。加固效果如下：

1. 配置 log_bin、log_error、general_log、slow_query_log 四项日志记录
2. 配置登录超时退出
3. 配置密码复杂度策略
4. 配置登录失败处理措施

```shell
[mysqld]
# 如使用 audit_log 插件，需要安装 audit_log.so 并添加以下内容
## 安装：INSTALL PLUGIN audit_log SONAME 'audit_log.so';
## 查询：SELECT * FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME LIKE '%audit_log%';
# plugin-load = audit_log.so
# audit_log_policy = ALL
# audit_log_format = JSON
# audit_log_file = /var/log/mysql/audit.log
# audit_log_rotate_on_size = 1G
# audit_log_rotations = 10

# 配置 mysql-bin.log
log_bin = /var/log/mysql/mysql-bin.log
server-id = 1

# 配置 mysql-general.log
general_log = 1
general_log_file = /var/log/mysql/mysql-general.log

# 配置 mysql-error.log
log_error = /var/log/mysql/mysql-error.log

# 配置 mysql-slow.log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/mysql-slow.log
long_query_time = 2 # 2 秒

# 登录超时退出
wait_timeout = 1800
interactive_timeout = 1800

# 密码过期时间
default_password_lifetime = 90

# 密码复杂度策略，需要安装 validate_password.so 插件.
## 安装：INSTALL PLUGIN validate_password SONAME 'validate_password.so';
## 检查：SELECT * FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME LIKE '%validate_password%';
validate_password_policy = MEDIUM
validate_password_length = 8
validate_password_mixed_case_count = 1
validate_password_number_count = 1
validate_password_special_char_count = 1

# 登录失败处理，需要安装 connection_control.so，默认已安装.
## 安装：INSTALL PLUGIN connection_control SONAME 'connection_control.so';
## 查询：SELECT * FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME LIKE '%connection_control%';
connection_control_failed_connections_threshold = 5
connection_control_min_connection_delay = 300000
```


### 配置日志保存半年

将所有日志默认留存时间设置为 28 周：`vim /etc/logrotate.conf/`

```shell
rotate 28
```

### 配置用户登录地址

```shell
# 查看用户信息
select user,host from mysql.user

# 修改用户登录地址
RENAME USER 'root'@'%' TO 'root'@'localhost'; # 或：UPDATE mysql.user SET host = 'localhost' WHERE user = 'root';

# 刷新权限
FLUSH PRIVILEGES;
```

### Mysql 数据库 + 配置文件备份

1. 了解数据备份命令

```shell
# 备份单个数据库
mysqldump -u [username] -p[password] [database_name] > [database_name].sql

# 备份多个数据库
mysqldump -u [username] -p[password] --databases [database_name1] [database_name2] > databases.sql

# 备份所有数据库
mysqldump -u [username] -p[password] --all-databases > all_databases.sql
```

2. 设置备份脚本

```shell
#!/bin/bash
# 保存备份的目录
BACKUP_DIR="/data/mysql_data_and_config_backup/"
# 配置文件路径
CONFIG_FILE="/etc/my.cnf"
# 数据库的用户名
DB_USER="your_username"
# 数据库的密码
DB_PASSWORD="your_password"
# 数据库名
DATABASE="your_database"

# 创建备份文件的时间戳
DATE=$(date +%Y%m%d_%H%M%S)
# 最终的备份文件
BACKUP_FILE="$BACKUP_DIR/$DATABASE_$DATE.sql"

# 使用 mysqldump 来备份数据库
mysqldump -u $DB_USER -p$DB_PASSWORD $DATABASE > $BACKUP_FILE
# 备份配置文件
cp $CONFIG_FILE "$BACKUP_DIR/my.cnf_$DATE"

# 可选：删除7天前的旧备份
# find $BACKUP_DIR -type f -mtime +7 -name '*.sql' -exec rm {} \;
```

3. 赋予执行权限

```shell
chmod +x mysql_data_and_config_backup.sh
```

4. 配置计划任务，7 日备份一次： `crontab -e`

```shell
0 1 * * * /path/to/your/mysql_data_and_config_backup.sh
```

### 配置三权用户

```shell
# 添加三权用户：安全管理员、审计管理员、操作管理员
CREATE USER 'sec_admin'@'localhost' IDENTIFIED BY 'password1';
CREATE USER 'audit_admin'@'localhost' IDENTIFIED BY 'password2';
CREATE USER 'op_admin'@'localhost' IDENTIFIED BY 'password3';

# 授予 sec_admin 添加用户、权限重载、查看所有数据库权限
GRANT CREATE USER, RELOAD, SHOW DATABASES ON *.* TO 'sec_admin'@'localhost';
# 授予 sec_admin 查看、插入、更新、删除 mysql 库权限
GRANT SELECT, INSERT, UPDATE, DELETE ON mysql.* TO 'sec_admin'@'localhost';


# 授予 audit_admin 用户查看所有数据库中的数据权限
GRANT SELECT ON *.* TO 'audit_admin'@'localhost';
# 授予 audit_admin 用户对 mysql 数据库中的 general_log 表进行查看、插入、更新、删除操作的权限
GRANT SELECT, INSERT, UPDATE, DELETE ON mysql.general_log TO 'audit_admin'@'localhost';
# 授予 audit_admin 用户对 mysql 数据库中的 slow_log 表进行查看、插入、更新、删除操作的权限
GRANT SELECT, INSERT, UPDATE, DELETE ON mysql.slow_log TO 'audit_admin'@'localhost';

# 授予 op_admin 用户对所有数据库的数据进行查看、插入、更新、删除操作的权限
GRANT SELECT, INSERT, UPDATE, DELETE ON *.* TO 'op_admin'@'localhost';
# 授予 op_admin 用户执行所有数据库中存储过程和函数的权限
GRANT EXECUTE ON *.* TO 'op_admin'@'localhost';
# 授予 op_admin 用户锁表、权限重载以及文件操作权限，适用于所有数据库
GRANT LOCK TABLES, RELOAD, FILE ON *.* TO 'op_admin'@'localhost';

# 刷新权限
FLUSH PRIVILEGES;

# 检查用户权限
SHOW GRANTS FOR 'username'@'host';
```

## Mysql 常用命令

### 数据库恢复

恢复到测试库用以测试，避免直接覆盖现有库。

```shell
CREATE DATABASE testdb;
mysql -u username -p testdb < /path/to/your/backup_file.sql
```