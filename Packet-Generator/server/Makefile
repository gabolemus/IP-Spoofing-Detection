program := packet-generator

# The executable needs to be run as root because it needs to open a raw socket

build-dbg:
	cargo build

run-dbg:
	target/debug/$(program)

build:
	cargo build --release

run:
	target/release/$(program)

clean:
	cargo clean

help:
	@echo "make <build-dbg|run-dbg|build|run|clean|help>"
