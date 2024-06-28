## 软件安装

### 安装 StrongSwan（Debian）

```shell
sudo apt update
sudo apt install libstrongswan libstrongswan-extra-plugins network-manager-strongswan strongswan strongswan-charon strongswan-libcharon strongswan-nm strongswan-pki libcharon-extra-plugins strongswan-charon strongswan-libcharon
```

### [安装 Docker](https://www.kali.org/docs/containers/installing-docker-on-kali/)（Debian）

```shell
sudo apt update
sudo apt install -y docker.io
sudo systemctl enable docker --now
# 将用户添加到 docker 组以使用`docker`不带`sudo`
sudo usermod -aG docker $USER
```

## 实用命令

### sed

```shell
# \n 替换为 ",
sed ':a;N;$!ba;s/\n/\",/g' inputfile
```

### tr 

```shell
# 替换 “ 为空
tr -d "\""

# 替换 " 为 \n
tr "\"" "\n"
```

### vim 

```shell
# 替换
:%s/-m tcp --dport 1521/-m multiport --dports 1521,6200/g
```

## 软件配置及使用

### Git

```shell
# 删除库内容
git rm -r --cached node_modules
```

### Docker

```shell
## 以下命令用以输出镜像启动后执行的任务信息，可用于排错
sudo docker start -ai 8ffd4daff884
```

###  Mysql

#### 开启 mysql 日志审计（企业版）

1. 安装日志审计插件

```shell
INSTALL PLUGIN audit_log SONAME 'audit_log.so';
```

2. 配置 `/etc/my.cnf`

```shell
[mysqld]
plugin-load = audit_log.so
audit_log_policy = ALL
audit_log_format = JSON
audit_log_file = /var/log/mysql/audit.log
audit_log_rotate_on_size = 1G
audit_log_rotations = 10
```

3. 重启 mysql

```shell
sudo systemctl restart mysqld
```

～ #### 开启 mysql 日志审计（社区版）～

1. 安装日志审计插件

```shell
INSTALL PLUGIN audit_log SONAME 'audit_log.so';
```

2. 配置 `/etc/my.cnf`

```shell
[mysqld]
plugin-load = audit_log.so
audit_log_policy = ALL
audit_log_format = JSON
audit_log_file = /var/log/mysql/audit.log
audit_log_rotate_on_size = 1G
audit_log_rotations = 10
```

3. 重启 mysql

```shell
sudo systemctl restart mysqld
```

#### 配置日志保存 180 日

1. 编辑 `/etc/logrotate.d/mysql-audit`，为 Mysql 日志配置 `logrotate`

```shell
/var/log/mysql/audit.log {
    daily
    rotate 180
    compress
    missingok
    notifempty
    copytruncate
}
```

2. 验证配置

```shell
sudo logrotate -d /etc/logrotate.d/mysql-audit
```


3. 手动运行一次日志轮换以测试配置

```shell
sudo logrotate -f /etc/logrotate.d/mysql-audit
```

#### 开启特定的日志记录

1. 配置 `my.cnf`，开启 log_bin、general_log、log_error、slow_query_log

```shell
[mysqld]
# mysql-bin.log
log_bin = /var/log/mysql/mysql-bin.log
server-id = 1

# mysql-general.log
general_log = 1
general_log_file = /var/log/mysql/mysql-general.log

# mysql-error.log
log_error = /var/log/mysql/mysql-error.log

# slow_query_log
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2 // 单位是秒
```

2. 重启 mysql 服务

```shell
sudo systemctl restart mysqld
```

#### 配置用户登录地址

1. 查看用户信息

```shell
select user,host from mysql.user
```

2. 修改用户登录地址

```shell
RENAME USER 'root'@'%' TO 'root'@'192.168.1.100';
# 或
UPDATE mysql.user SET host = '192.168.1.100' WHERE user = 'root';
```

3. 刷新权限

```shell
FLUSH PRIVILEGES;
```

#### Mysql 业务数据 + 配置数据备份备份

1. 数据备份命令了解

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
BACKUP_DIR="/path/to/your/backup/directory"
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

# 可选：删除7天前的旧备份
find $BACKUP_DIR -type f -mtime +7 -name '*.sql' -exec rm {} \;
```

3. 赋予执行权限

```shell
chmod +x backup.sh
```

4. 配置计划任务

```shell
crontab -e
0 1 * * * /path/to/your/backup.sh
```

5. 配置数据备份

```shell
#!/bin/bash

# 配置文件的路径（根据你的实际情况进行修改）
CONFIG_FILE="/etc/mysql/my.cnf"
# 备份目录
BACKUP_DIR="/path/to/your/backup/directory"
# 创建备份文件的时间戳
DATE=$(date +%Y%m%d)

# 备份配置文件
cp $CONFIG_FILE "$BACKUP_DIR/my.cnf_$DATE"


chmod +x backup_mysql_config.sh


crontab -e
0 1 */7 * * /path/to/your/backup_mysql_config.sh

```

#### Mysql 数据恢复

```shell
CREATE DATABASE testdb;
mysql -u username -p testdb < /path/to/your/backup_file.sql
```

# 基线加固

### 密码复杂度设置

```shell
cp /etc/pam.d/s/system-auth /etc/pam.d/s/system-auth.20240628.bak
vim /etc/pam.d/system-auth
password  requisite  pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type= minlen=10 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1 enforce_for_root
```

### 密码过期
```shell
vim /etc/login.defs
PASS_MAX_DAYS 90
```

###  日志备份

```shell
#!/bin/bash
BACKUP_DIR="/data/system_log/"
DATE=$(date +%Y%m%d)
BACKUP_FILE="$BACKUP_DIR/system_log_backup_$DATE.tar.gz"
mkdir -p $BACKUP_DIR
tar -czf $BACKUP_FILE /var/log/

sudo chmod +x /usr/local/bin/backup_logs.sh

crontab -e
0 3 1 * * /usr/local/bin/backup_logs.sh
```




