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

compose-up:
	docker compose up -d

compose-down:
	docker compose down && rm -rf ./tcpdump

compose-start:
	docker compose start

compose-stop:
	docker compose stop && rm -rf ./tcpdump

compose-recreate:
	docker compose down && docker image prune -a -f && docker compose up -d

help:
	@echo "make <build-dbg|run-dbg|build|run|clean|compose-up|compose-down|compose-start|compose-stop|compose-recreate|help>"
