# SSH

## 内网穿透之 ssh 反向隧道

1. vps 的 `/etc/ssh/sshd_config`，`GatewayPorts` 参数值为 `yes`。然后重启 ssh 服务：`systemctl restart sshd.service`
   
2. 以下命令均在内网电脑执行，切换为 root 用户：`su root`
   
3. 安装 autossh：`apt install autossh`
   
4. 新建 `/root/sshPortMapping.sh`,输入以下内容：
   
    ```shell
    autossh -M 7890 -ngfNTR 80:127.0.0.1:22 root@150.158.84.84 -o "PubkeyAuthentication=yes" -o "StrictHostKeyChecking=false" -o "PasswordAuthentication=no" -o "ServerAliveInterval 60" -o "ServerAliveCountMax 3" -i ~/.ssh/id_rsa

5. 赋予 `/root/sshPortMapping.sh` 执行权限：`chmod +x /root/sshPortMapping.sh`
   
6. 新建：`/usr/lib/systemd/system/autosshd.service`

    ```shell
    [Unit]
    Description=Auto SSH Tunnel
    After=network-online.target
    StartLimitInterval=10
    [Service]
    User=root
    Type=simple
    ExecStart=/bin/bash /root/sshPortMapping.sh
    ExecReload=/bin/kill -HUP $MAINPID
    KillMode=process
    Restart=always
    RestartSec=5
    [Install]
    WantedBy=multi-user.target
    WantedBy=graphical.target
    WantedBy=default.target
    ```

7. 配置 `autosshd.service` 开机自启动：`systemctl enable autosshd.service`
   
8. 启动服务：`systemctl start autosshd`
