APP_NAME := dns-proxy
BUILD_DIR := bin

.PHONY: all build run test clean fmt

all: build

build:
	go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/dns-proxy

run: build
	./$(BUILD_DIR)/$(APP_NAME)

test:
	go test -v ./...

clean:
	rm -rf $(BUILD_DIR)

fmt:
	go fmt ./...
