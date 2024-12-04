## ERROR: Get "https://registry-1.docker.io/v2/": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)

1. 有就备份修改，冇则新建。`sudo vim /etc/docker/daemon.json`,填入以下内容：

```json
{
    "dns": ["8.8.8.8", "8.8.4.4"],
    "registry-mirrors":
        [
            "https://docker.m.daocloud.io/",
            "https://huecker.io/",
            "https://dockerhub.timeweb.cloud",
            "https://noohub.ru/",
            "https://dockerproxy.com",
            "https://docker.mirrors.ustc.edu.cn",
            "https://docker.nju.edu.cn",
            "https://xx4bwyg2.mirror.aliyuncs.com",
            "http://f1361db2.m.daocloud.io",
            "https://registry.docker-cn.com",
            "http://hub-mirror.c.163.com",
            "https://docker.mirrors.ustc.edu.cn"
        ]
}
```

2. 重启服务
```shell
systemctl daemon-reload 
systemctl restart docker
```