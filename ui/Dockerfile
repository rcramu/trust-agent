FROM node:22-alpine AS build
WORKDIR /src

COPY ui/package.json ui/package-lock.json /src/ui/
RUN npm ci --prefix /src/ui

COPY evaluation/results/approach_comparison.json /src/evaluation/results/approach_comparison.json
COPY ui /src/ui
RUN npm run build --prefix /src/ui

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY ui/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/ui/dist /usr/share/nginx/html
EXPOSE 8080
