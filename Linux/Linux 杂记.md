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