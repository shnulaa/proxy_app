# 使用 Node.js 官方镜像作为基础镜像
FROM node:16
 
# 指定工作目录
WORKDIR /app
 
# 复制 package.json 和 package-lock.json
COPY package*.json ./
 
# 安装依赖项
RUN npm install
 
# 复制应用程序代码
COPY . .
 
# 暴露应用程序端口
EXPOSE 8888
 
# 启动应用程序
CMD ["npm", "start"]
