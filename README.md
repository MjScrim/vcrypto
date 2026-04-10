# vCrypto 🔐
**Virtual Cryptographic Hardware Coprocessor (Linux Kernel Module)**

> **Status:** Work in Progress (Active Development)

`vCrypto` is a Linux Kernel driver (Ring 0) designed to simulate a physical cryptographic hardware coprocessor. Instead of allocating isolated buffers per user session, this module implements a **Global Hardware State** architecture, acting as a single shared resource across the operating system.

## Architecture & Core Concepts

This project is built to demonstrate robust kernel-space engineering, focusing on thread safety, memory management, and process isolation.

* **Singleton Hardware Simulation:** The device state is allocated once at module initialization (`__init`) using `kmalloc`. It simulates a single physical chip soldered to the motherboard.
* **Concurrency & Thread Safety:** Because the hardware buffer is a shared global resource, `vCrypto` implements strict **Mutex locking** (`mutex_lock` / `mutex_unlock`). This prevents Race Conditions and memory corruption when multiple user-space threads (Ring 3) attempt to read/write concurrently.
* **Exclusive Access (Access Control):** The `open` and `release` file operations act as a hardware gatekeeper. If Process A opens the device, it returns `-EBUSY` to any other process attempting to connect, enforcing strict exclusive access.
* **Miscdevice Interface:** Utilizes the Linux `miscdevice` API for clean dynamic minor number allocation and boilerplate reduction, while manually handling the lifecycle in the initialization phase.
* **Pointer Arithmetic:** Implements the `container_of` macro to safely retrieve the primary data structure from the generic `file->private_data` pointer during I/O operations.

## Current Development Phase

The module is currently compilable and can be loaded into the kernel via `insmod`.
- [x] Global memory allocation and device registration.
- [x] Mutex initialization and Race Condition protection.
- [x] File operations boilerplate (`open`, `release`, `read`, `write`).
- [x] IOCTL interface skeleton (`VCRYPTO_SET_KEY`, `VCRYPTO_RESET`).
- [ ] User-space CLI tool implementation for testing.
- [ ] Advanced encryption algorithms integration.

## Building and Loading

*(Instructions will be updated as the Makefile structure is finalized).*

```bash
make
sudo insmod vcrypto.ko
dmesg | tail
```

# Developed by Marcos Andrade for architectural study of the Linux Kernel.
