# SSH

## 内网穿透之 ssh 反向隧道

### 0x01 autossh 命令各参数含义

-   **`-M 7890`**：  
    指定用于监控连接状态的端口。`autossh` 会通过这个端口来检测 SSH 隧道是否正常工作，如果发现连接中断，它会尝试自动重新建立连接。
    
      
    
-   **`-n`**：  
    将标准输入重定向到 `/dev/null`，这通常用于让命令在后台运行时不会受到终端输入的影响，避免命令因等待终端输入而阻塞。
    
      
    
-   **`-g`**：  
    允许远程主机连接到本地转发的端口，使得远程主机上的其他进程（如果有权限）也可以访问通过隧道转发过来的服务。
    
      
    
-   **`-f`**：  
    让 `autossh` 命令在后台运行，也就是进入 “守护进程” 模式，这样命令执行后不会占用当前终端会话，你可以继续在终端中执行其他操作。
    
      
    
-   **`-N`**：  
    表示不执行远程命令，仅仅建立 SSH 隧道连接，因为这里的目的是做端口转发，而不是在远程服务器上执行具体的命令行操作。
    
      
    
-   **`-T`**：  
    禁用伪终端分配，对于只进行端口转发等不需要终端交互的情况，可以提高效率并避免一些不必要的问题。
    
      
    
-   **`-R 80:127.0.0.1:22`**：  
    这是关键的端口转发配置参数。表示在远程服务器（`150.158.84.84`）上，将其 `80` 端口绑定并转发到本地（发起连接的这一端）的 `127.0.0.1` 的 `22` 端口。这样，当远程服务器的 `80` 端口接收到请求时，数据会通过 SSH 隧道转发到本地的 SSH 服务（运行在 `127.0.0.1` 的 `22` 端口）上。
    
      
    
-   **`root@150.158.84.84`**：  
    指定要连接的远程服务器的用户名（`root`）和 IP 地址（`150.158.84.84`），意味着将以 `root` 用户身份通过 SSH 协议连接到对应的远程主机。
    
      
    
-   **`-o "PubkeyAuthentication=yes"`**：  
    配置 SSH 连接选项，这里表示启用公钥认证方式。也就是使用本地保存的 SSH 密钥（在后面指定的 `~/.ssh/id_rsa`）来进行身份验证，而不是通过密码等其他方式，这种方式更加安全且方便自动化操作。
    
      
    
-   **`-o "StrictHostKeyChecking=false"`**：  
    关闭严格的主机密钥检查。正常情况下，SSH 连接时会验证远程服务器的主机密钥是否与本地缓存中记录的匹配，设置为 `false` 意味着会自动接受新的主机密钥，不过这样存在一定安全风险，在不太在意严格验证或者明确信任连接目标的场景下可这样设置，比如测试环境等，在生产环境使用需谨慎。
    
      
    
-   **`-o "PasswordAuthentication=no"`**：  
    明确禁止使用密码认证方式进行 SSH 连接，结合前面启用公钥认证，进一步确保连接只能通过 SSH 密钥来完成身份验证，增强安全性。
    
      
    
-   **`-o "ServerAliveInterval 60"`**：  
    设置 SSH 客户端每隔 `60` 秒向服务器发送一个保持连接的消息（心跳包），用于检测连接是否正常，防止因网络空闲等原因导致连接被服务器端断开。
    
      
    
-   **`-o "ServerAliveCountMax 3"`**：  
    指定在没有收到服务器对心跳包的响应后，客户端最多尝试 `3` 次发送心跳包，如果仍然没有响应，则客户端认为连接已经断开，此时 `autossh` 会根据前面配置的监控端口等机制尝试重新建立连接。
    
      
    
-   **`-i ~/.ssh/id_rsa`**：  
    指定用于 SSH 公钥认证的私钥文件路径，这里就是使用本地用户主目录下 `.ssh` 文件夹中的 `id_rsa` 文件作为私钥，对应的公钥（通常是 `id_rsa.pub`）应该已经被添加到了远程服务器的 `authorized_keys` 文件中，用于验证用户身份。

### 0x02 配置步骤

1. vps 的 `/etc/ssh/sshd_config`，`GatewayPorts` 参数值为 `yes`。然后重启 ssh 服务：`systemctl restart sshd.service`
   
2. 以下命令均在内网电脑执行，切换为 root 用户：`su root`
   
3. 安装 autossh：`apt install autossh`
   
4. 新建 `/root/sshPortMapping.sh`,输入以下内容：
   
    ```shell
    autossh -M 7890 -ngfNTR 80:127.0.0.1:22 root@150.158.84.84 -o "PubkeyAuthentication=yes" -o "StrictHostKeyChecking=false" -o "PasswordAuthentication=no" -o "ServerAliveInterval 60" -o "ServerAliveCountMax 3" -i ~/.ssh/id_rsa
    ```

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

6. 重启 SSH 服务
```shell
service ssh restart
```