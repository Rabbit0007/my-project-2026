ARG NODE_BASE_IMAGE=docker.io/library/node:25-alpine
ARG NGINX_BASE_IMAGE=docker.io/library/nginx:1.27-alpine

FROM ${NODE_BASE_IMAGE} AS build

WORKDIR /src
COPY package.json package-lock.json* ./
RUN npm config set registry https://registry.npmmirror.com && npm install
COPY . .
RUN npm run build

FROM ${NGINX_BASE_IMAGE}
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 80
