# ---------- Build stage ----------
FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache dependencies first.
COPY go.mod go.sum ./
RUN go mod download

# Build the static binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/agent ./cmd/agent

# ---------- Runtime stage ----------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app

COPY --from=build /bin/agent /app/agent
COPY --from=build /src/wordlists ./wordlists

RUN mkdir -p /app/reportes

ENV PORT=8080
EXPOSE 8080

CMD ["/app/agent"]
