FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /enclout ./cmd/enclout

FROM alpine:3.21

RUN apk add --no-cache ca-certificates sqlite
COPY --from=builder /enclout /usr/local/bin/enclout

EXPOSE 8080

ENTRYPOINT ["enclout"]
CMD ["serve", "--bind", "0.0.0.0:8080", "--db", "/data/enclout.db"]
