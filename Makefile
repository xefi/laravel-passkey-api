.PHONY: help setup test test-coverage bash
.DEFAULT_GOAL := help

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

vendor/autoload.php: composer.json
	docker-compose run --rm php composer install

setup: ## Build docker image and install dependencies
	docker-compose build
	docker-compose run --rm php composer install

test: vendor/autoload.php ## Run PHPUnit tests
	docker-compose run --rm php vendor/bin/phpunit

test-coverage: vendor/autoload.php ## Run PHPUnit tests with code coverage
	docker-compose run --rm php vendor/bin/phpunit --coverage-html coverage

bash: ## Open a bash shell in the PHP container
	docker-compose run --rm php bash
