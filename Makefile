.PHONY: all kernel lib cli clean

all: kernel lib cli

kernel:
	@echo "[+] Compiling the Kernel Module (Ring 0)..."
	@$(MAKE) -C src/kernel

lib:
	@echo "[+] Compiling the Shared Library (Ring 3)..."
	@$(MAKE) -C src/lib

cli:
	@echo "[+] Compiling the commandline interface (CLI)..."
	@$(MAKE) -C src/cli

clean:
	@echo "[!] Cleaning Kernel binaries..."
	@$(MAKE) -C src/kernel clean
	@echo "[!] Cleaning up binaries from the Library..."
	@$(MAKE) -C src/lib clean
	@echo "[!] Clearing CLI binaries..."
	@$(MAKE) -C src/cli clean
	@echo "[+] Complete cleaning."
