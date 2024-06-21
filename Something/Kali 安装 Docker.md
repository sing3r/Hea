---
created: 2024-06-21T21:02:14 (UTC +08:00)
tags: [kali,linux,kalilinux,Penetration,Testing,Penetration Testing,Distribution,Advanced]
source: https://www.kali.org/docs/containers/installing-docker-on-kali/
author: 
---

# 在 Kali Linux 上安装 Docker | Kali Linux 文档

> ## Excerpt
> To install Docker on Kali you need to remember that there is already a package named “docker”, therefore Docker has to be installed under a different name. If you install docker you will not end up with the container version. The version we will be installing is named docker.io. All commands are the same however, so running docker on the command line will be the appropriate command:

---
## 在 Kali Linux 上安装 Docker

目录

-  [在 Kali Linux 上安装 docker-ce](https://www.kali.org/docs/containers/installing-docker-on-kali//#installing-docker-ce-on-kali-linux)
-  [参考](https://www.kali.org/docs/containers/installing-docker-on-kali//#references)

要在 Kali 上安装 Docker，您需要记住，已经有一个名为“docker”的软件包，因此必须使用其他名称安装 Docker。如果您安装，则`docker`不会得到容器版本。我们将要安装的版本名为`docker.io`。但是，所有命令都相同，因此`docker`在命令行上运行将是适当的命令：

```shell
kali@kali:~$ sudo apt update
kali@kali:~$
kali@kali:~$ sudo apt install -y docker.io
kali@kali:~$
kali@kali:~$ sudo systemctl enable docker --now
kali@kali:~$
kali@kali:~$ docker
kali@kali:~$
```

现在，您可以开始使用 docker，使用`sudo`。如果您想将自己添加到 docker 组以使用`docker`不带`sudo`，则需要执行额外的步骤：

```
kali@kali:~$ sudo usermod -aG docker $USER
kali@kali:~$
```

最后一件事是**退出并再次登录**。

如果您想使用 Kali Docker 镜像，我们[这里](https://www.kali.org/docs/containers/using-kali-docker-images/)有一个相关文档页面。

[

##### 在 Kali Linux 上安装 docker-ce

](https://www.kali.org/docs/containers/installing-docker-on-kali//#installing-docker-ce-on-kali-linux)

`docker-ce`可以从 Docker 存储库安装。需要记住的一点是，[Kali Linux 基于 Debian](https://www.kali.org/docs/policy/kali-linux-relationship-with-debian/)，因此我们需要使用[Debian 当前的稳定版本](https://www.debian.org/releases/stable/)（即使 Kali Linux 是一个[滚动发行版](https://www.kali.org/docs/general-use/kali-branches/)）。在撰写本文时（2023 年 12 月），它的“书虫”：

```
kali@kali:~$ echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list 
```

导入 gpg 密钥：

```
kali@kali:~$ curl -fsSL https://download.docker.com/linux/debian/gpg |
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
```

安装最新版本的`docker-ce`：

```
kali@kali:~$ sudo apt update
kali@kali:~$ sudo apt install -y docker-ce docker-ce-cli containerd.io
```

[参考](https://www.kali.org/docs/containers/installing-docker-on-kali//#references)

[在 Debian 上安装 Docker Engine](https://docs.docker.com/engine/install/debian/)

___

更新于：2024-Mar-01  
作者： [gamb1t](https://gitlab.com/gamb1t "gamb1t 的个人资料") 、 [elreydetoda](https://gitlab.com/elreydetoda "elreydetoda 的个人资料")

___

[installing-docker-on-kali/index.md](https://gitlab.com/-/ide/project/kalilinux/documentation/kali-docs/edit/master/-/containers/installing-docker-on-kali/index.md)
