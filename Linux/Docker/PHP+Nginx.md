## php:7.4-fpm
```shell
docker pull php:7.4-fpm # 获取 php:7.4-fpm 镜像
docker run -p 9000:9000 -d --name php.0 php:7.4-fpm
mkdir /home/user/php-fpm		# 映射配置文件的本地路径
docker cp php.0:/usr/local/etc/php /home/user/php-fpm			# copy全部配置文件至本地路径
mv /home/user/php-fpm/php/* /home/user/php-fpm/
rm /home/user/php-fpm/php/
docker stop php.0 && docker rm php.0		# 停止并删除辅助容器
docker run -p 9000:9000 -d --name php.1 -v /home/user/php-fpm:/usr/local/etc/php/ php:7.4-fpm
```

## nginx
```shell
docker pull nginx
docker run --name nginx.0 -p 80:80 -d nginx
mkdir /home/user/www/html		# 映射页面文件的本地路径
mkdir /home/user/nginx/conf.d		# 映射配置文件的本地路径
docker cp nginx.0:/usr/share/nginx/html /home/user/www/		# copy全部页面文件至本地路径
docker cp /etc/nginx/conf.d /home/user/nginx/			# copy全部配置文件至本地路径
docker stop nginx.0 && docker rm nginx.0		# 停止并删除辅助容器
docker run --name nginx.1 -p 80:80 -d -v /home/user/www/html:/usr/share/nginx/html -v /home/user/nginx/conf.d:/etc/nginx/conf.d nginx
```

### 修改 /home/user/nginx/conf.d/default.conf
```shell
server {
    listen       80;	# 监听80端口
    listen  [::]:80;
    server_name  localhost;		# 也可以填写自己注册的域名
    location / {
        root   /usr/share/nginx/html;	# 当前配置的页面文件根目录
        index  index.php index.html index.htm;	# 添加index.php作为默认首页
    }
    # error_page  404              /404.html;
    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;		# 错误页面设置
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
    # 与php-fpm通信的关键设置
    location ~ \.php$ {
         root   /usr/share/nginx/html;	# 页面文件根目录
         fastcgi_pass   php.1容器的ip:9000;	# php-fpm的通信端口，由于已经将容器9000端口映射到了主机的9000端口，所以这里填“主机ip:9000”也是可以的。
         fastcgi_index  index.php;		# 默认主页文件设置
         fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
         fastcgi_param  SCRIPT_NAME      $fastcgi_script_name;
         include        fastcgi_params;
    }
}
```