# 玄盾 Web管理控制台 — 静态资源服务
# 构建前需先执行: npm install && npx vite build
# 构建: docker build -t xuandun-console:1.3.2 -f admin-console/Dockerfile .
FROM nginx:1.27-alpine

LABEL maintainer="DaoTi XuanDun Team"
LABEL description="XuanDun Admin Console - Web Management Interface"
LABEL version="1.3.2"

# 复制构建产物
COPY admin-console/dist/ /usr/share/nginx/html/

# Nginx 配置：SPA fallback + API 代理
COPY admin-console/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
