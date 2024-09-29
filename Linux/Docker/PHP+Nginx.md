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
mkdir /home/user/nginx/logs		# 映射配置文件的本地路径
docker cp nginx.0:/usr/share/nginx/html /home/user/www/		# copy全部页面文件至本地路径
docker cp /etc/nginx/conf.d /home/user/nginx/			# copy全部配置文件至本地路径
docker stop nginx.0 && docker rm nginx.0		# 停止并删除辅助容器
docker run --name nginx.1 -p 80:80 -d -v /home/user/nginx/logs:/var/log/nginx -v /home/user/www/html:/usr/share/nginx/html -v /home/user/nginx/conf.d:/etc/nginx/conf.d nginx
```

### 修改 /home/user/nginx/conf.d/default.conf
```shell
server {
    listen       80;
    listen  [::]:80;
    server_name  localhost;

    # 设置默认访问日志路径
    access_log  /var/log/nginx/access.log;

    # 静态资源不记录日志
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        access_log off;
        root /usr/share/nginx/html;
    }

    location / {
        root   /usr/share/nginx/html;
        index  index.php index.html index.htm;
    }

    #error_page  404              /404.html;

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }

    # proxy the PHP scripts to Apache listening on 127.0.0.1:80
    #
    #location ~ \.php$ {
    #    proxy_pass   http://127.0.0.1;
    #}

    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    location ~ \.php$ {
        root           /usr/share/nginx/html;
        fastcgi_pass   172.17.0.2:9000; # 修改为 php.1 容器地址
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
	#fastcgi_param  SCRIPT_NAME      $fastcgi_script_name;
        include        fastcgi_params;
    }

    # deny access to .htaccess files, if Apache's document root
    # concurs with nginx's one
    #
    #location ~ /\.ht {
    #    deny  all;.

    #}
}
```