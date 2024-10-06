FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y wget git gcc-12 g++ make cmake pkg-config libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev libopengl-dev libglx-dev libglu1-mesa-dev freeglut3-dev libxxf86vm-dev

ENV GO_VERSION=1.23.0
RUN wget -qP /tmp "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz"
RUN tar -C /usr/local -xzf "/tmp/go${GO_VERSION}.linux-amd64.tar.gz"
RUN rm "/tmp/go${GO_VERSION}.linux-amd64.tar.gz"
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

WORKDIR /app
COPY . .
RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc) bundling_target

RUN cd frontend/desktop && go build -o /previewer ./cmd/previewer
RUN cd tools/web-previewer && go build -o /preview-server .

FROM ubuntu:22.04 AS runner
WORKDIR /app
RUN apt-get update && apt-get -y install ca-certificates
COPY --from=builder /previewer /preview-server ./

CMD ["/app/preview-server", "-previewer", "/app/previewer"]
