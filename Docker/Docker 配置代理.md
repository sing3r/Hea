## docker 配置代理

1. `sudo vim /usr/lib/systemd/system/docker.service`
2. `[Service]` 标签插入：
```shell
[Service]
Environment="HTTP_PROXY=http://127.0.0.1:8123"
Environment="HTTPS_PROXY=http://127.0.0.1:8123"
```
3. 重启服务：
```shell
sudo systemctl daemon-reload
sudo systemctl restart docker
```