FROM docker.io/library/golang:1.23-bookworm AS builder
WORKDIR /go/src/github.com/moriyoshi/badass-mail-handler
COPY . .
RUN go build -o /tmp/badass ./cmd/badass

FROM docker.io/library/debian:bookworm AS debug
RUN install -d /opt/badass/bin /opt/badass/etc
COPY --from=builder /tmp/badass /opt/badass/bin/badass
ENTRYPOINT ["/opt/badass/bin/badass"]

FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=builder /tmp/badass /opt/badass/bin/badass
ENTRYPOINT ["/opt/badass/bin/badass"]