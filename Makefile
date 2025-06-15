.PHONY: build install clean test

# Variables
BINARY_NAME=sqd-network-monitor
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.buildTime=$(BUILD_TIME)"
INSTALL_DIR=/usr/local/bin
CONFIG_DIR=/etc/sqd-network-monitor

# Build the agent
build:
	@echo "Building $(BINARY_NAME)..."
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/sqd-network-monitor

# Install the agent
install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	install -m 755 $(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Creating config directory $(CONFIG_DIR)..."
	mkdir -p $(CONFIG_DIR)
	@if [ ! -f $(CONFIG_DIR)/config.yaml ]; then \
		echo "Installing default config to $(CONFIG_DIR)/config.yaml..."; \
		install -m 644 config.yaml.example $(CONFIG_DIR)/config.yaml; \
	else \
		echo "Config file already exists, not overwriting."; \
	fi
	@echo "Installing systemd service..."
	install -m 644 sqd-network-monitor.service /etc/systemd/system/
	@echo "Reloading systemd..."
	systemctl daemon-reload
	@echo "Installation complete. To start the service, run: systemctl enable --now sqd-network-monitor"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Build a Debian package
deb:
	@echo "Building Debian package..."
	mkdir -p build/deb/DEBIAN
	mkdir -p build/deb/usr/local/bin
	mkdir -p build/deb/etc/sqd-network-monitor
	mkdir -p build/deb/etc/systemd/system
	cp $(BINARY_NAME) build/deb/usr/local/bin/
	cp config.yaml.example build/deb/etc/sqd-network-monitor/config.yaml
	cp sqd-network-monitor.service build/deb/etc/systemd/system/
	echo "Package: sqd-network-monitor" > build/deb/DEBIAN/control
	echo "Version: 0.1.0" >> build/deb/DEBIAN/control
	echo "Section: utils" >> build/deb/DEBIAN/control
	echo "Priority: optional" >> build/deb/DEBIAN/control
	echo "Architecture: amd64" >> build/deb/DEBIAN/control
	echo "Maintainer: Nodexeus <support@nodexeus.com>" >> build/deb/DEBIAN/control
	echo "Description: SQD Node Monitoring Agent" >> build/deb/DEBIAN/control
	echo " Monitors and manages SQD nodes running on the server." >> build/deb/DEBIAN/control
	echo "#!/bin/sh" > build/deb/DEBIAN/postinst
	echo "systemctl daemon-reload" >> build/deb/DEBIAN/postinst
	echo "echo 'To start the service, run: systemctl enable --now sqd-network-monitor'" >> build/deb/DEBIAN/postinst
	chmod 755 build/deb/DEBIAN/postinst
	dpkg-deb --build build/deb sqd-network-monitor_0.1.0_amd64.deb
	rm -rf build/deb
