## SSH 服务配置
```shell
# 不允许空密码登录
PermitEmptyPasswords no
# 不允许 root 用户远程登录
PermitRootLogin no

# 指定 SSH 传输加密算法。查询 ssh 支持的加密算法命令：ssh -Q cipher
Ciphers aes256-ctr，aes192-ctr，aes128-ctr

# 配置用户及组黑白名单
AllowUsers user1 user2
AllowGroups group1 group2
DenyUsers user3 user4
DenyGroups group3 group4

# 每个连接允许的最大验证尝试次
MaxAuthTries 4

# 指定 MAC 算法。查询 ssh 支持的 MAC 加密算法命令：ssh -Q mac
MACs hmac-sha2-512，hmac-sha2-256

# 设置服务器向客户端发送空闲连接消息的频率
ClientAliveInterval 300

# 置在服务器终止客户端会话之前，未收到客户端响应的最大请求（alive消息）数量
ClientAliveCountMax 3
```

## 用户帐户和环境
```shell
# 配置密码过期时间
## 配置新用户的密码默认过期时间为 30 日
useradd -D -f 30
## 修改已存在用户的密码过期时间
chage --inactive 30 <user>

# 密码修改最小时间间隔
## vim /etc/login.defs
PASS_MIN_DAYS 7
PASS_MAX_DAYS 90

chage --mindays 7 <user>
chage --maxdays 90 <user>
```

## 配置 PAM
```shell
# 密码重用记录
## (/etc/pam.d/system-auth && /etc/pam.d/password-auth) || /etc/pam.d/common-password
password sufficient pam_unix.so remember=5

# 密码复杂度设置
## (/etc/pam.d/system-auth && /etc/pam.d/password-auth) || /etc/pam.d/common-password
password requisite pam_pwquality.so try_first_pass retry=3 minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1

auth required pam_env.so
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth sufficient pam_unix.so nullok try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth requisite pam_succeed_if.so uid >= 500 quiet
auth required pam_deny.so
```