.PHONY: help analyse check check-full clean cs-check cs-fix deptrac docs hooks infection install md-check md-fix md-lint phpmd psalm psalm-taint rector rector-fix sbom security test test-coverage

# Use php84 for compatibility with xdebug
PHP ?= php84

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

analyse: ## Run PHPStan static analysis
	$(PHP) vendor/bin/phpstan analyse --memory-limit=512M

check: security cs-check analyse psalm phpmd rector deptrac test ## Run all checks (without mutation testing)

check-full: check infection psalm-taint ## Run all checks including mutation testing and taint analysis

clean: ## Clean build artifacts
	rm -rf vendor build docs/api .rector .phpunit.cache .php-cs-fixer.cache .psalm .deptrac.cache

cs-check: ## Check code style
	$(PHP) vendor/bin/php-cs-fixer fix --dry-run --diff

cs-fix: ## Fix code style
	$(PHP) vendor/bin/php-cs-fixer fix

deptrac: ## Run architecture analysis
	$(PHP) vendor/bin/deptrac analyse

docs: ## Generate API documentation
	@mkdir -p build/bin
	@test -f build/bin/phpDocumentor.phar || curl -sSL https://phpdoc.org/phpDocumentor.phar -o build/bin/phpDocumentor.phar
	$(PHP) build/bin/phpDocumentor.phar

hooks: ## Install git hooks (CaptainHook)
	vendor/bin/captainhook install --force

infection: ## Run mutation testing
	@mkdir -p build/bin && ln -sf /usr/bin/php84 build/bin/php
	PATH="$(CURDIR)/build/bin:$(PATH)" PCOV_ENABLED=1 $(PHP) -d extension=pcov.so -d pcov.enabled=1 vendor/bin/infection --threads=4 --initial-tests-php-options="-d extension=pcov.so -d pcov.enabled=1"

install: ## Install dependencies
	composer install

md-check: ## Check markdown formatting (Prettier)
	pnpm dlx prettier --check "**/*.md"

md-fix: ## Fix markdown formatting (Prettier)
	pnpm dlx prettier --write "**/*.md"

md-lint: ## Lint markdown files
	npx --yes markdownlint-cli2 "**/*.md"

phpmd: ## Run PHP Mess Detector
	$(PHP) vendor/bin/phpmd src text phpmd.xml

psalm: ## Run Psalm static analysis
	$(PHP) vendor/bin/psalm --show-info=false

psalm-taint: ## Run Psalm taint analysis
	$(PHP) vendor/bin/psalm --taint-analysis

rector: ## Check for Rector suggestions
	$(PHP) vendor/bin/rector process --dry-run

rector-fix: ## Apply Rector fixes
	$(PHP) vendor/bin/rector process

sbom: ## Generate Software Bill of Materials
	composer sbom

security: ## Run security audit
	composer audit --no-dev

test: ## Run tests
	$(PHP) vendor/bin/phpunit

test-coverage: ## Run tests with coverage report (pcov)
	$(PHP) -d extension=pcov.so -d pcov.enabled=1 vendor/bin/phpunit --coverage-text --coverage-html=build/coverage --coverage-clover=build/coverage.xml

.DEFAULT_GOAL := help
