FROM nginx:1.27-alpine

COPY apps/dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY apps/dashboard/index.html /usr/share/nginx/html/index.html
COPY apps/dashboard/styles.css /usr/share/nginx/html/styles.css
COPY apps/dashboard/app.js /usr/share/nginx/html/app.js

EXPOSE 80
