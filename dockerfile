FROM golang:1.21.6

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY . . 

RUN go build -o go-service ./cmd

EXPOSE 8080

CMD ["./go-service"]