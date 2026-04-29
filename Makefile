.PHONY: help build run clean test push deploy k8s-deploy k8s-clean

# Variables
IMAGE_NAME ?= elevadr
IMAGE_TAG ?= latest
REGISTRY ?= docker.io/yourregistry
FULL_IMAGE = $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

help: ## Show this help message
	@echo "eleVADR - OT Network Security Analysis Tool"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build Docker image
	@echo "Building Docker image: $(IMAGE_NAME):$(IMAGE_TAG)"
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

run: ## Run analysis with Docker (requires pcaps/capture.pcap)
	@echo "Running analysis..."
	@mkdir -p pcaps reports
	docker run --rm \
		-v $(PWD)/pcaps:/input:ro \
		-v $(PWD)/reports:/output \
		$(IMAGE_NAME):$(IMAGE_TAG)

run-compose: ## Run analysis with docker-compose
	@echo "Running with docker-compose..."
	@mkdir -p pcaps reports
	docker-compose up elevadr

web-server: ## Start web server to view reports
	@echo "Starting report web server on http://localhost:8080"
	docker-compose --profile web-server up -d report-server

stop-web: ## Stop web server
	docker-compose --profile web-server down

clean: ## Clean up generated files and containers
	@echo "Cleaning up..."
	docker-compose down -v
	rm -rf app/data/zeeks/*
	rm -rf reports/*.json

clean-all: clean ## Clean everything including Docker images
	docker rmi $(IMAGE_NAME):$(IMAGE_TAG) || true

push: build ## Push image to registry
	@echo "Tagging and pushing to $(FULL_IMAGE)"
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(FULL_IMAGE)
	docker push $(FULL_IMAGE)

# Kubernetes targets
k8s-deploy: ## Deploy to Kubernetes
	@echo "Deploying to Kubernetes..."
	kubectl apply -k k8s/

k8s-status: ## Check Kubernetes deployment status
	@echo "Checking deployment status..."
	kubectl get all -n elevadr

k8s-logs: ## View logs from latest job
	@echo "Fetching logs..."
	kubectl logs -n elevadr -l app=elevadr --tail=100 -f

k8s-clean: ## Remove Kubernetes resources
	@echo "Removing Kubernetes resources..."
	kubectl delete -k k8s/

# Development targets
test-local: ## Run analysis locally (requires Python venv)
	@echo "Running local analysis..."
	cd app && python main.py

install-deps: ## Install Python dependencies
	pip install -r requirements.txt

format: ## Format code with black
	black app/

lint: ## Lint code
	pylint app/ || true
	flake8 app/ || true

# Quick setup
setup-dirs: ## Create necessary directories
	@echo "Creating directories..."
	mkdir -p pcaps reports
	mkdir -p app/data/uploads
	mkdir -p app/data/zeeks
	mkdir -p app/data/zeek_scripts
	mkdir -p app/data/assessor_data

download-oui: ## Download and parse OUI data
	python app/utils/download_and_parse_oui.py

# Example usage
example: setup-dirs ## Show example usage
	@echo ""
	@echo "Example Usage:"
	@echo "=============="
	@echo ""
	@echo "1. Place your PCAP in pcaps/capture.pcap"
	@echo "2. Run: make run"
	@echo "3. View report: cat reports/report.json"
	@echo ""
