compose-up:
	docker compose up -d

compose-down:
	docker compose down && rm -rf ./tcpdump ./traffic-analysis

compose-start:
	docker compose start

compose-stop:
	docker compose stop && rm -rf ./tcpdump ./traffic-analysis

compose-recreate:
	docker compose down && docker image prune -a -f && docker compose up -d

help:
	@echo "make <compose-up|compose-down|compose-start|compose-stop|compose-recreate|help>"
