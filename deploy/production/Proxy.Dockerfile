FROM mirror.gcr.io/library/nginx:1.27-alpine
COPY frontend/dist/ /usr/share/nginx/html/
RUN chmod -R a+rX /usr/share/nginx/html
COPY deploy/production/nginx.conf.template /etc/nginx/nginx.conf.template
COPY deploy/production/start-nginx.sh /usr/local/bin/start-nginx
RUN chmod 755 /usr/local/bin/start-nginx
ENTRYPOINT ["/usr/local/bin/start-nginx"]
