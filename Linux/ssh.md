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

## no matching host key type found 问题

1. 连接 Ubuntu 24.10 服务器版 SSH 服务出现问题。
2. 开启 debug 模式检查问题,发现算法报错。

    ```shell
    ssh -v username@ip_adrr
    ```

3. 通过 journal 查看详细错误信息：

    ```shell
    > journal -l | grep ssh
    Nov 26 11:05:52 scale-mode sshd[7744]: Unable to negotiate with 1.1.1.1 port 40143: no matching MAC found. Their offer: hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96 [preauth]
    Nov 26 10:43:23 scale-mode sshd[7191]: Unable to negotiate with 1.1.1.1 port 36131: no matching host key type found. Their offer: ssh-rsa,ssh-dss [preauth]
    ```

4. 根据提示修改 Ubuntu 24.10 服务器 SSH 配置文件用以解决问题：
   
    ```shell
    Ciphers aes256-ctr,aes192-ctr,aes128-ctr
    # 解决 no matching host key type found
    MACs hmac-sha1,hmac-sha2-512,hmac-sha2-256
    # 解决 no matching MAC found
    HostKey /etc/ssh/ssh_host_rsa_key
    HostKeyAlgorithms ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521
    ```

5. 检查配置是否存在问题

    ```shell
    sshd -t
    ```