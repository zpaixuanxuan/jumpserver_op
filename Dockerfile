FROM python:3.6
MAINTAINER zhangpan "zhangpan@qianxin.com"
RUN mkdir /app
WORKDIR /app
ADD . /app/
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
RUN sed -i 's#http://deb.debian.org#https://mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list
RUN sed -i 's#http://security.debian.org#https://mirrors.tuna.tsinghua.edu.cn#g' /etc/apt/sources.list
RUN apt update && apt install libldap2-dev libssl-dev libsasl2-dev git -y
RUN cd /app && pip install -r requirements/requirements.txt
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]