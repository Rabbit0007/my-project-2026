ARG GO_BASE_IMAGE=docker.io/library/golang:1.25-alpine
ARG ALPINE_BASE_IMAGE=docker.io/library/alpine:3.21

FROM ${GO_BASE_IMAGE} AS build

WORKDIR /src
RUN apk add --no-cache git
ENV GOPROXY=https://goproxy.cn,direct
ENV GOSUMDB=sum.golang.google.cn
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/worker ./cmd/worker

FROM ${ALPINE_BASE_IMAGE}

WORKDIR /app
RUN apk add --no-cache ca-certificates curl grep findutils
COPY --from=build /out/api /app/api
COPY --from=build /out/worker /app/worker
RUN mkdir -p /app/workspace
EXPOSE 18080
CMD ["/app/api"]
