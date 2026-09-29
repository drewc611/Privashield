FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

COPY apps/dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY apps/dashboard/index.html /usr/share/nginx/html/index.html
COPY apps/dashboard/styles.css /usr/share/nginx/html/styles.css
COPY apps/dashboard/app.js /usr/share/nginx/html/app.js

EXPOSE 80
