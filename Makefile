VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -X distrike/cmd.Version=$(VERSION)

# Build for current platform
build:
	go build -ldflags "$(LDFLAGS)" -o distrike$(shell go env GOEXE) .

# Cross-compile release binaries
release:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/distrike_windows_amd64.exe .
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/distrike_linux_amd64     .
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/distrike_darwin_amd64    .
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/distrike_darwin_arm64    .

install: build
	install -m755 distrike$(shell go env GOEXE) $(GOPATH)/bin/distrike$(shell go env GOEXE)

clean:
	rm -f distrike distrike.exe
	rm -rf dist/

.PHONY: build release install clean
