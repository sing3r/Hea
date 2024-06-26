## sed

```shell
# \n 替换为 ",
sed ':a;N;$!ba;s/\n/\",/g' inputfile
```

## tr 

```shell
# 替换 “ 为空
tr -d "\""

# 替换 " 为 \n
tr "\"" "\n"
```

## vim 

```shell
# 替换
:%s/-m tcp --dport 1521/-m multiport --dports 1521,6200/g
```