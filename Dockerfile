FROM golang:1.23.2-bookworm AS builder
RUN apt-get update && apt-get install -y wget git gcc-12 g++ make cmake pkg-config libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev libopengl-dev libglx-dev libglu1-mesa-dev freeglut3-dev libxxf86vm-dev libpng-dev

WORKDIR /app
COPY . .
RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make -j$(nproc) bundling_target

RUN cd frontend/desktop && go build -o /previewer ./cmd/previewer
RUN cd tools/web-previewer && go build -o /preview-server .

FROM debian:12 AS runner
WORKDIR /app
RUN apt-get update && apt-get -y install ca-certificates
COPY --from=builder /previewer /preview-server ./

CMD ["/app/preview-server", "-previewer", "/app/previewer"]
