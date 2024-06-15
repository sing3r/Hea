# Debian 或基于 Debian 的系统安装 StrongSwan
1. 安装
```shell
sudo apt update
sudo apt install libstrongswan libstrongswan-extra-plugins network-manager-strongswan strongswan strongswan-charon strongswan-libcharon strongswan-nm strongswan-pki libcharon-extra-plugins strongswan-charon strongswan-libcharon
```
2. 配置
   1. Name：随便填写；
   2. Address：x.x.x.x；
   3. Certificate：选择证书；
   4. Username：用户名；
   5. Password：密码；
   6. Options：打勾 Request an inner IP address 和 Enforce UDP encapsulation；

