## jumpserver_op系统
### 1 当前功能：
* 用户管理-用户增删改查
* 运维导航-快速链接、导航面板管理-增删改查
* 统一账户体系，支持LDAP登录、本地用户登录，开启LDAP的情况下，用户改密码实时同步到LDAP，新增用户直接可以添加到LDAP账户体系中
* LDAP账户修改一些属性同步到LDAP
### 2 待添加功能
* 导航权限分配
* 支持接入开源没有账户体系的系统
* 其他

欢迎有兴趣的同学一起开发，这里感谢[Jumpserver](https://github.com/jumpserver/)这么好的项目，借用了框架。

### 3. 运行项目
```shell
bash docker-auto-deployment.sh
```

### 4. 服务访问

```shell
# 访问
http://127.0.0.1:8080
用户名 ： admin
密码： admin

```

### 5. nginx配置
生产环境，请把配置中DEBUG改为False
```
#nginx配置文件
server {
	listen 80;
	listen 443 ssl http2;
	server_name 域名; #配置自己的域名

	#https配置，没有的可以忽略
	#ssl on;
	#ssl_certificate ***.cer;  #替换为自己的路径
	#ssl_certificate_key ***.key; #替换为自己的路径
	#ssl_session_timeout 5m;
	#ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
	#ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
	#ssl_prefer_server_ciphers on;

	index index.html index.htm index.php;

	proxy_set_header X-Real-IP $remote_addr;
	proxy_set_header Host $host;
	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

	location /media/ {
		root /opt/diting/data/;
	}

	location /static/ {
		root /opt/diting/data/;
	}

	location / {
		proxy_pass http://localhost:8080;
	}

}
```
