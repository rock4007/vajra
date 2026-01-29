# Vajra Kavach - Cloud Deployment Guide

## Quick Start Options

### 1. Docker Compose (Local/Single Server)

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f backend

# Stop services
docker-compose down

# Access backend at http://localhost:8080
```

---

## 2. Kubernetes (Production)

### Prerequisites
- kubectl configured
- Kubernetes cluster (EKS, AKS, GKE, or on-prem)
- Docker image pushed to registry

### Deploy to Kubernetes

```bash
# Create namespace
kubectl create namespace vajra

# Create ConfigMap
kubectl apply -f k8s-configmap.yaml -n vajra

# Create Secrets
kubectl create secret generic vajra-secrets \
  --from-literal=smtp_host=$SMTP_HOST \
  --from-literal=smtp_user=$SMTP_USER \
  --from-literal=smtp_pass=$SMTP_PASS \
  --from-literal=twilio_sid=$TWILIO_SID \
  --from-literal=twilio_token=$TWILIO_TOKEN \
  -n vajra

# Deploy application
kubectl apply -f k8s-deployment.yaml -n vajra

# Monitor deployment
kubectl rollout status deployment/vajra-backend -n vajra

# Get service info
kubectl get svc -n vajra
kubectl get pods -n vajra
```

---

## 3. AWS Deployment

### Option A: ECS (Elastic Container Service)

```bash
# Build Docker image
docker build -t vajra-backend:latest .

# Tag for ECR
docker tag vajra-backend:latest $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/vajra-backend:latest

# Push to ECR
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/vajra-backend:latest

# Create ECS task definition and service using AWS Console or CLI
```

### Option B: EKS (Elastic Kubernetes Service)

```bash
# Create EKS cluster
eksctl create cluster --name vajra --region us-east-1

# Configure kubectl
aws eks update-kubeconfig --name vajra --region us-east-1

# Deploy using Kubernetes manifests
kubectl apply -f k8s-deployment.yaml
```

### Option C: Elastic Beanstalk

```bash
# Create .ebextensions/python.config
# Deploy with EB CLI
eb create vajra-env
eb deploy
```

---

## 4. Azure Deployment

### Option A: Azure Container Instances (ACI)

```bash
# Build and push to ACR
az acr build --registry $ACR_NAME --image vajra-backend:latest .

# Deploy to ACI
az container create \
  --resource-group $RG_NAME \
  --name vajra-container \
  --image $ACR_NAME.azurecr.io/vajra-backend:latest \
  --cpu 1 \
  --memory 1 \
  --port 8008 \
  --environment-variables \
    ALERT_EMAILS=$ALERT_EMAILS \
    ALERT_PHONES=$ALERT_PHONES
```

### Option B: Azure Kubernetes Service (AKS)

```bash
# Create AKS cluster
az aks create --resource-group $RG_NAME --name vajra-cluster --node-count 3

# Get credentials
az aks get-credentials --resource-group $RG_NAME --name vajra-cluster

# Deploy
kubectl apply -f k8s-deployment.yaml
```

### Option C: Azure App Service

```bash
# Create App Service Plan
az appservice plan create --name vajra-plan --resource-group $RG_NAME --sku B2 --is-linux

# Create Web App
az webapp create --resource-group $RG_NAME --plan vajra-plan --name vajra-app --runtime "PYTHON:3.11"

# Deploy from Docker
az webapp config container set --name vajra-app --resource-group $RG_NAME \
  --docker-custom-image-name $ACR_NAME.azurecr.io/vajra-backend:latest \
  --docker-registry-server-url https://$ACR_NAME.azurecr.io
```

---

## 5. Google Cloud Platform (GCP)

### Option A: Cloud Run

```bash
# Build and deploy
gcloud run deploy vajra-backend \
  --source . \
  --platform managed \
  --region us-central1 \
  --memory 512Mi \
  --cpu 1 \
  --timeout 120 \
  --set-env-vars ALERT_EMAILS=$ALERT_EMAILS,ALERT_PHONES=$ALERT_PHONES
```

### Option B: GKE (Google Kubernetes Engine)

```bash
# Create GKE cluster
gcloud container clusters create vajra-cluster --num-nodes=3 --region us-central1

# Get credentials
gcloud container clusters get-credentials vajra-cluster --region us-central1

# Deploy
kubectl apply -f k8s-deployment.yaml
```

### Option C: Compute Engine

```bash
# Create VM instance
gcloud compute instances create vajra-vm \
  --image-family debian-11 \
  --image-project debian-cloud \
  --machine-type e2-medium \
  --zone us-central1-a

# SSH and install Docker
gcloud compute ssh vajra-vm --zone us-central1-a
docker-compose up -d
```

---

## 6. DigitalOcean

```bash
# Create Droplet
doctl compute droplet create vajra-droplet \
  --region nyc3 \
  --image docker-20-04 \
  --size s-1vcpu-1gb

# SSH to droplet
ssh root@<droplet-ip>

# Clone repository and run
git clone <repo-url>
cd VajraBackend
docker-compose up -d
```

---

## 7. Heroku

```bash
# Create Heroku app
heroku create vajra-backend

# Add buildpacks
heroku buildpacks:add --index 1 heroku/python

# Deploy
git push heroku main

# View logs
heroku logs -t
```

---

## Environment Variables Setup

Create `.env` file for Docker:

```bash
# Alert Configuration
ALERT_EMAILS=your-email@example.com
ALERT_PHONES=+91XXXXXXXXXX
ALERT_NTFY_TOPICS=vajra-alerts

# SMTP Configuration (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Twilio Configuration (Optional)
TWILIO_SID=your-twilio-sid
TWILIO_TOKEN=your-twilio-token
TWILIO_FROM=+1XXXXXXXXXX

# Flask Configuration
FLASK_ENV=production
FLASK_DEBUG=0
```

---

## Monitoring & Logging

### AWS CloudWatch
```bash
# View logs in CloudWatch
aws logs tail /aws/ecs/vajra --follow
```

### Azure Monitor
```bash
# Create Application Insights
az monitor app-insights component create \
  --app vajra-insights \
  --location eastus \
  --resource-group $RG_NAME
```

### GCP Cloud Logging
```bash
# View logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=vajra-backend"
```

---

## Scaling Configuration

### Horizontal Pod Autoscaler (Kubernetes)
- Min replicas: 2
- Max replicas: 10
- CPU target: 70%
- Memory target: 80%

### Auto Scaling Group (AWS EC2)
- Min instances: 2
- Max instances: 10
- Target CPU: 70%

---

## SSL/TLS Setup

### Self-Signed Certificate (Dev)
```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

### Let's Encrypt (Production)
```bash
# Using Certbot with nginx
certbot certonly --nginx -d yourdomain.com
```

---

## Database (Optional - for persistence)

Add PostgreSQL to docker-compose.yml:

```yaml
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - vajra-network

volumes:
  postgres_data:
```

---

## Performance Optimization

1. **Enable Caching**
   - Redis cache layer for frequent queries

2. **CDN Setup**
   - CloudFront (AWS), Azure CDN, or Cloud CDN (GCP)

3. **Load Balancing**
   - Application Load Balancer or Network Load Balancer

4. **Database Optimization**
   - Read replicas for databases
   - Connection pooling

---

## Security Checklist

- [x] Run as non-root user in containers
- [x] Use security headers (implemented in app)
- [x] Enable rate limiting (implemented)
- [x] Input validation & sanitization (implemented)
- [ ] Network policies in Kubernetes
- [ ] WAF rules in cloud provider
- [ ] Secrets management (use cloud provider secrets)
- [ ] SSL/TLS enforcement
- [ ] DDoS protection (enable in cloud provider)

---

## Backup & Disaster Recovery

### Database Backups
```bash
# AWS RDS automatic backups
# Azure Backup for databases
# Google Cloud SQL backups
```

### Application State
```bash
# Daily snapshots of EBS/disks
# Regular backups of logs to S3/Blob Storage
```

---

## Cost Optimization

- Use reserved instances for consistent workload
- Leverage spot instances for non-critical tasks
- Implement auto-scaling to reduce idle capacity
- Use edge locations for content delivery

---

## Support & Resources

- Documentation: See DOCUMENTATION.md
- Security: See SECURITY_HARDENING_COMPLETE.md
- Local Development: See README.md

