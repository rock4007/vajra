#!/bin/bash

# Vajra Backend - Cloud Deployment Script
# Supports AWS, Azure, GCP, and Docker Compose

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check dependencies
check_dependencies() {
    print_header "Checking Dependencies"
    
    local deps=("docker" "docker-compose" "git")
    
    for cmd in "${deps[@]}"; do
        if command -v $cmd &> /dev/null; then
            print_success "$cmd is installed"
        else
            print_error "$cmd is not installed"
            return 1
        fi
    done
}

# Deploy with Docker Compose
deploy_docker_compose() {
    print_header "Deploying with Docker Compose"
    
    if [ ! -f "docker-compose.yml" ]; then
        print_error "docker-compose.yml not found"
        return 1
    fi
    
    print_warning "Building images..."
    docker-compose build
    
    print_warning "Starting services..."
    docker-compose up -d
    
    print_warning "Waiting for services to be ready..."
    sleep 10
    
    if docker-compose ps | grep -q "Up"; then
        print_success "Services started successfully"
        print_success "Backend: http://localhost:8008"
        print_success "Nginx: http://localhost:80"
        print_success "Prometheus: http://localhost:9090"
        return 0
    else
        print_error "Services failed to start"
        docker-compose logs
        return 1
    fi
}

# Deploy to AWS
deploy_aws() {
    print_header "Deploying to AWS"
    
    print_warning "Checking AWS CLI..."
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI not installed"
        return 1
    fi
    
    print_warning "Building Docker image..."
    docker build -t vajra-backend:latest .
    
    print_warning "Pushing to ECR..."
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    AWS_REGION=${AWS_REGION:-us-east-1}
    ECR_REPO="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/vajra-backend"
    
    aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
    docker tag vajra-backend:latest $ECR_REPO:latest
    docker push $ECR_REPO:latest
    
    print_success "Image pushed to ECR: $ECR_REPO"
    print_warning "Next: Create ECS task or deploy with kubectl to EKS"
}

# Deploy to Azure
deploy_azure() {
    print_header "Deploying to Azure"
    
    print_warning "Checking Azure CLI..."
    if ! command -v az &> /dev/null; then
        print_error "Azure CLI not installed"
        return 1
    fi
    
    print_warning "Building Docker image..."
    docker build -t vajra-backend:latest .
    
    ACR_NAME=${ACR_NAME:-vajraacr}
    print_warning "Pushing to Azure Container Registry..."
    az acr build --registry $ACR_NAME --image vajra-backend:latest .
    
    print_success "Image pushed to ACR"
    print_warning "Next: Deploy to AKS or Container Instances"
}

# Deploy to GCP
deploy_gcp() {
    print_header "Deploying to Google Cloud"
    
    print_warning "Checking gcloud CLI..."
    if ! command -v gcloud &> /dev/null; then
        print_error "gcloud CLI not installed"
        return 1
    fi
    
    print_warning "Building Docker image..."
    docker build -t vajra-backend:latest .
    
    GCP_PROJECT=${GCP_PROJECT:-$(gcloud config get-value project)}
    GCP_REGION=${GCP_REGION:-us-central1}
    
    print_warning "Pushing to Google Container Registry..."
    docker tag vajra-backend:latest gcr.io/$GCP_PROJECT/vajra-backend:latest
    docker push gcr.io/$GCP_PROJECT/vajra-backend:latest
    
    print_success "Image pushed to GCR"
    print_warning "Next: Deploy to Cloud Run or GKE"
}

# Deploy to Kubernetes
deploy_kubernetes() {
    print_header "Deploying to Kubernetes"
    
    print_warning "Checking kubectl..."
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl not installed"
        return 1
    fi
    
    print_warning "Creating namespace..."
    kubectl create namespace vajra || true
    
    print_warning "Creating ConfigMap..."
    kubectl apply -f k8s-configmap.yaml -n vajra
    
    print_warning "Creating Secrets..."
    kubectl create secret generic vajra-secrets \
      --from-literal=SMTP_HOST=${SMTP_HOST} \
      --from-literal=SMTP_USER=${SMTP_USER} \
      --from-literal=SMTP_PASS=${SMTP_PASS} \
      --from-literal=TWILIO_SID=${TWILIO_SID} \
      --from-literal=TWILIO_TOKEN=${TWILIO_TOKEN} \
      --from-literal=TWILIO_FROM=${TWILIO_FROM} \
      -n vajra --dry-run=client -o yaml | kubectl apply -f -
    
    print_warning "Deploying application..."
    kubectl apply -f k8s-deployment.yaml -n vajra
    
    print_warning "Waiting for deployment..."
    kubectl rollout status deployment/vajra-backend -n vajra
    
    print_success "Deployment completed"
    kubectl get pods -n vajra
}

# Show deployment status
show_status() {
    print_header "Deployment Status"
    
    if docker-compose ps 2>/dev/null | grep -q "Up"; then
        print_success "Docker Compose services:"
        docker-compose ps
    fi
    
    if command -v kubectl &> /dev/null; then
        print_success "Kubernetes deployments:"
        kubectl get deployments -n vajra 2>/dev/null || echo "No Kubernetes cluster connected"
    fi
}

# Clean up resources
cleanup() {
    print_header "Cleanup"
    
    read -p "Delete Docker containers and volumes? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker-compose down -v
        print_success "Docker Compose cleaned up"
    fi
    
    read -p "Delete Kubernetes resources? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        kubectl delete namespace vajra --ignore-not-found
        print_success "Kubernetes resources cleaned up"
    fi
}

# Main menu
main_menu() {
    print_header "Vajra Backend - Cloud Deployment"
    
    echo "Select deployment option:"
    echo "1) Docker Compose (Local)"
    echo "2) Kubernetes (All Clouds)"
    echo "3) AWS (ECS/EKS)"
    echo "4) Azure (ACI/AKS)"
    echo "5) Google Cloud (Cloud Run/GKE)"
    echo "6) Show Status"
    echo "7) Cleanup"
    echo "8) Exit"
    echo
    
    read -p "Enter option (1-8): " choice
    
    case $choice in
        1) deploy_docker_compose ;;
        2) deploy_kubernetes ;;
        3) deploy_aws ;;
        4) deploy_azure ;;
        5) deploy_gcp ;;
        6) show_status ;;
        7) cleanup ;;
        8) exit 0 ;;
        *) print_error "Invalid option" ;;
    esac
}

# Main execution
if [ "$#" -eq 0 ]; then
    main_menu
else
    case "$1" in
        docker-compose) deploy_docker_compose ;;
        kubernetes) deploy_kubernetes ;;
        aws) deploy_aws ;;
        azure) deploy_azure ;;
        gcp) deploy_gcp ;;
        status) show_status ;;
        cleanup) cleanup ;;
        *) echo "Usage: $0 {docker-compose|kubernetes|aws|azure|gcp|status|cleanup}" ;;
    esac
fi
