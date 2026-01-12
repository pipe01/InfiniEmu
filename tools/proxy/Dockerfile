FROM golang:1.25-alpine
WORKDIR /app
COPY proxy.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/proxy proxy.go

CMD ["/app/proxy"]
