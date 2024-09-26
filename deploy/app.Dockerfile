# Этап сборки
FROM golang:1.23 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o ./cmd/main ./cmd/main.go

# Финальный этап
FROM alpine:latest

WORKDIR /app/cmd

COPY --from=builder /app/cmd/main .

EXPOSE 8080

CMD ["./main"]
