.PHONY: install test lint format run clean

# Install dependencies
install:
	pip install -r requirements.txt
	pip install -e .

# Run tests
test:
	pytest tests/ -v --cov=src

# Lint code
lint:
	flake8 src/ tests/
	mypy src/

# Format code
format:
	black src/ tests/

# Run the application
run:
	python -m src.main

# Clean up
clean:
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete
	rm -rf build/ dist/ *.egg-info/
	rm -rf .pytest_cache/ .coverage htmlcov/

# Development setup
dev-setup: install
	pre-commit install

# Create sample test directories
create-samples:
	mkdir -p samples/{python-flask,javascript-react,php-laravel,java-spring}
