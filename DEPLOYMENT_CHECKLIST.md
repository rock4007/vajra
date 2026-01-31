# Vajra Backend - Production Deployment Checklist

## Pre-Deployment Requirements

### System Requirements
- [ ] Docker and Docker Compose installed
- [ ] kubectl configured (for Kubernetes)
- [ ] Cloud CLI tools (aws, az, gcloud)
- [ ] Git repository cloned
- [ ] SSL/TLS certificates ready
- [ ] Domain name configured
- [ ] Sufficient cloud storage quota

### Credentials & Secrets
- [ ] SMTP credentials for email alerts
- [ ] Twilio API credentials for SMS/voice
- [ ] Database credentials (if using external DB)
- [ ] Cloud provider API keys
- [ ] SSL certificate and private key
- [ ] Database backups configured

### Environment Configuration
- [ ] `.env` file created from `.env.template`
- [ ] All required environment variables set
- [ ] Alert recipients configured
- [ ] CORS origins configured
- [ ] Rate limiting parameters tuned

---

## Security Hardening Checklist

### Application Security
- [x] Input validation and sanitization
- [x] SQL injection protection
- [x] Command injection protection
- [x] XSS protection
- [x] Prompt injection detection
- [x] CSRF/CORS protection
- [x] Rate limiting enabled
- [x] Security headers added
- [x] Running as non-root user
- [ ] WAF rules configured (cloud provider)
- [ ] DDoS protection enabled (cloud provider)

### Network Security
- [ ] VPC/VNet configured
- [ ] Security groups configured
- [ ] Network policies in Kubernetes
- [ ] TLS/SSL enabled
- [ ] Firewall rules configured
- [ ] VPN/Private endpoints configured

### Secrets Management
- [ ] Secrets not in code
- [ ] Environment variables used
- [ ] Cloud provider secrets manager configured
- [ ] Rotation policies set
- [ ] Access control configured

---

## Local Development Deployment (Docker Compose)

### 1. Prepare Environment
```bash
# Copy environment template
cp .env.template .env

# Edit .env with your values
nano .env
```

### 2. Build and Start Services
```bash
# Build Docker images
docker-compose build

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f backend
```

### 3. Verify Deployment
```bash
# Check service status
docker-compose ps

# Test health endpoint
curl http://localhost:8008/health

# View metrics
curl http://localhost:8008/metrics

# Access services
# Backend: http://localhost:8008
# Nginx: http://localhost:80
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/admin)
```

### 4. Stop Services
```bash
docker-compose down
docker-compose down -v  # Remove volumes
```

---

## Kubernetes Deployment (Production)

### 1. Prerequisites
```bash
# Install kubectl
# Configure kubeconfig
# Create Kubernetes cluster (EKS, AKS, or GKE)
```

### 2. Deploy Application
```bash
# Create namespace
kubectl create namespace vajra

# Create ConfigMap
kubectl apply -f k8s-configmap.yaml -n vajra

# Create Secrets
kubectl create secret generic vajra-secrets \
  --from-literal=SMTP_HOST=smtp.gmail.com \
  --from-literal=SMTP_USER=your-email@gmail.com \
  --from-literal=SMTP_PASS=your-app-password \
  --from-literal=TWILIO_SID=your-sid \
  --from-literal=TWILIO_TOKEN=your-token \
  --from-literal=TWILIO_FROM=+1XXXXXXXXXX \
  -n vajra

# Deploy
kubectl apply -f k8s-deployment.yaml -n vajra
```

### 3. Verify Deployment
```bash
# Check deployment status
kubectl rollout status deployment/vajra-backend -n vajra

# View pods
kubectl get pods -n vajra

# View services
kubectl get svc -n vajra

# View logs
kubectl logs -l app=vajra -n vajra -f

# Port forward for testing
kubectl port-forward -n vajra svc/vajra-backend 8008:8008
curl http://localhost:8008/health
```

### 4. Scale and Monitor
```bash
# Scale replicas
kubectl scale deployment vajra-backend --replicas=5 -n vajra

# View metrics
kubectl top nodes
kubectl top pods -n vajra

# Setup monitoring
kubectl apply -f prometheus-service.yaml -n vajra
```

---

## AWS Deployment (ECS/EKS)

### Option 1: ECS (Elastic Container Service)

#### 1. Create ECR Repository
```bash
aws ecr create-repository --repository-name vajra-backend --region us-east-1
```

#### 2. Build and Push Image
```bash
# Get AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=us-east-1

# Build image
docker build -t vajra-backend:latest .

# Tag for ECR
docker tag vajra-backend:latest $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/vajra-backend:latest

# Login to ECR
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# Push image
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/vajra-backend:latest
```

#### 3. Create ECS Task Definition
```bash
aws ecs register-task-definition --cli-input-json file://ecs-task-definition.json
```

#### 4. Create ECS Service
```bash
aws ecs create-service \
  --cluster vajra-cluster \
  --service-name vajra-backend \
  --task-definition vajra-backend:1 \
  --desired-count 3 \
  --load-balancers targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=backend,containerPort=8008
```

### Option 2: EKS (Elastic Kubernetes Service)

#### 1. Create EKS Cluster
```bash
eksctl create cluster --name vajra --region us-east-1 --nodes 3 --node-type t3.medium
```

#### 2. Deploy to EKS
```bash
# Configure kubectl
aws eks update-kubeconfig --name vajra --region us-east-1

# Deploy using kubectl
kubectl apply -f k8s-deployment.yaml -n vajra

# Setup load balancer
kubectl apply -f aws-load-balancer.yaml -n vajra
```

---

## Azure Deployment (ACI/AKS)

### Option 1: Azure Container Instances (ACI)

```bash
# Create resource group
az group create --name vajra-rg --location eastus

# Create ACR
az acr create --resource-group vajra-rg --name vajraacr --sku Basic

# Build and push image
az acr build --registry vajraacr --image vajra-backend:latest .

# Deploy to ACI
az container create \
  --resource-group vajra-rg \
  --name vajra-container \
  --image vajraacr.azurecr.io/vajra-backend:latest \
  --ports 8008 \
  --environment-variables \
    ALERT_EMAILS=your-email@example.com \
    ALERT_PHONES=+91XXXXXXXXXX
```

### Option 2: Azure Kubernetes Service (AKS)

```bash
# Create AKS cluster
az aks create \
  --resource-group vajra-rg \
  --name vajra-cluster \
  --node-count 3 \
  --vm-set-type VirtualMachineScaleSets

# Get credentials
az aks get-credentials --resource-group vajra-rg --name vajra-cluster

# Deploy
kubectl apply -f k8s-deployment.yaml -n vajra
```

---

## Google Cloud Platform (GCP) Deployment

### Option 1: Cloud Run

```bash
# Build and deploy directly
gcloud run deploy vajra-backend \
  --source . \
  --platform managed \
  --region us-central1 \
  --memory 512Mi \
  --cpu 1 \
  --timeout 120 \
  --set-env-vars "ALERT_EMAILS=your-email@example.com,ALERT_PHONES=+91XXXXXXXXXX"

# Get service URL
gcloud run services describe vajra-backend --region us-central1
```

### Option 2: GKE (Google Kubernetes Engine)

```bash
# Create GKE cluster
gcloud container clusters create vajra-cluster \
  --num-nodes 3 \
  --region us-central1 \
  --machine-type n1-standard-1

# Get credentials
gcloud container clusters get-credentials vajra-cluster --region us-central1

# Deploy
kubectl apply -f k8s-deployment.yaml -n vajra
```

---

## Post-Deployment Verification

### Health Checks
```bash
# Test health endpoint
curl http://<your-domain>/health

# Check metrics
curl http://<your-domain>/metrics

# Test API
curl -X POST http://<your-domain>/webhook \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

### Monitoring
```bash
# View Prometheus metrics
# Navigate to http://<your-domain>:9090

# View Grafana dashboards
# Navigate to http://<your-domain>:3000
# Login: admin/admin (change password!)
```

### Logs
```bash
# Docker Compose
docker-compose logs -f backend

# Kubernetes
kubectl logs -l app=vajra -n vajra -f

# AWS CloudWatch
aws logs tail /aws/ecs/vajra --follow

# Azure
az container logs --resource-group vajra-rg --name vajra-container

# GCP
gcloud logging read "resource.type=cloud_run_revision"
```

---

## Updating & Rollback

### Kubernetes Rolling Update
```bash
# Update image
kubectl set image deployment/vajra-backend \
  backend=<new-image> -n vajra

# Monitor rollout
kubectl rollout status deployment/vajra-backend -n vajra

# Rollback if needed
kubectl rollout undo deployment/vajra-backend -n vajra
```

### Docker Compose Update
```bash
# Pull latest image
docker-compose pull

# Restart services
docker-compose up -d
```

---

## Troubleshooting

### Services Won't Start
```bash
# Check logs
docker-compose logs backend

# Check port availability
netstat -an | grep 8008

# Remove containers and retry
docker-compose down
docker-compose up -d
```

### High Memory Usage
```bash
# Check container stats
docker stats

# Adjust memory limits in docker-compose.yml

# Restart
docker-compose restart
```

### Database Connection Issues
```bash
# Verify database is running
docker-compose ps

# Check database logs
docker-compose logs postgres

# Test connection
psql postgresql://user:pass@localhost:5432/vajra
```

### Kubernetes Pod Crashes
```bash
# Check pod status
kubectl describe pod <pod-name> -n vajra

# View pod logs
kubectl logs <pod-name> -n vajra

# Check events
kubectl get events -n vajra --sort-by='.lastTimestamp'
```

---

## Performance Optimization

### Load Testing
```bash
# Using Apache Bench
ab -n 10000 -c 100 http://localhost:8008/health

# Using wrk
wrk -t12 -c100 -d30s http://localhost:8008/health
```

### Metrics to Monitor
- Response time (< 100ms)
- Error rate (< 0.1%)
- Throughput (requests/sec)
- CPU usage (< 80%)
- Memory usage (< 80%)
- Disk usage (< 90%)

---

## Maintenance & Backups

### Database Backups
```bash
# Backup PostgreSQL
docker exec vajra-postgres pg_dump -U postgres vajra > backup.sql

# Restore
cat backup.sql | docker exec -i vajra-postgres psql -U postgres vajra
```

### Log Retention
```bash
# Configure log rotation
docker-compose.yml: logging driver setup

# Archive logs
find ./logs -mtime +30 -exec gzip {} \;
```

---

## Cost Optimization

- [ ] Use reserved instances for steady workload
- [ ] Leverage spot instances for non-critical tasks
- [ ] Enable auto-scaling to reduce idle capacity
- [ ] Use edge locations for content delivery
- [ ] Regular audit of resources
- [ ] Set up billing alerts

---

## Support & Escalation

- Local Issues: See logs and Docker stats
- Kubernetes Issues: Check kubectl describe and events
- Cloud Provider Issues: Use cloud provider support
- Security Issues: See SECURITY_HARDENING_COMPLETE.md
- Performance Issues: Run load tests and analyze metrics

