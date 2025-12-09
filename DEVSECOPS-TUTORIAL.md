# DevSecOps Tutorial
## Integrating Security into Development and Operations

---

## Table of Contents
1. [What is DevSecOps?](#what-is-devsecops)
2. [CI/CD Pipeline Fundamentals](#cicd-pipeline-fundamentals)
3. [Version Control and Git Workflows](#version-control-and-git-workflows)
4. [Container Security](#container-security)
5. [Infrastructure as Code (IaC)](#infrastructure-as-code-iac)
6. [Security Testing Automation](#security-testing-automation)
7. [Secrets Management](#secrets-management)
8. [Monitoring and Observability](#monitoring-and-observability)
9. [Practical CI/CD Examples](#practical-cicd-examples)

---

## What is DevSecOps?

**DevSecOps** = Development + Security + Operations

Traditional approach:
```
Development → Operations → Security (afterthought)
```

DevSecOps approach:
```
┌─────────────────────────────────────────┐
│  Development ←→ Security ←→ Operations  │
│        (Continuous Collaboration)       │
└─────────────────────────────────────────┘
```

### Core Principles

1. **Shift Left**: Integrate security early in development
2. **Automation**: Automate security testing and compliance
3. **Continuous Monitoring**: Real-time security monitoring
4. **Collaboration**: Security is everyone's responsibility
5. **Fast Feedback**: Quick security feedback to developers

### DevSecOps Lifecycle

```
┌──────────────────────────────────────────────────────┐
│                     PLAN                             │
│  Threat modeling, Security requirements             │
└────────────────┬─────────────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────────────┐
│                     CODE                             │
│  IDE security plugins, Secure coding practices       │
└────────────────┬─────────────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────────────┐
│                    BUILD                             │
│  SAST, Dependency scanning, Container scanning       │
└────────────────┬─────────────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────────────┐
│                     TEST                             │
│  DAST, Penetration testing, Security testing         │
└────────────────┬─────────────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────────────┐
│                   DEPLOY                             │
│  Secure deployments, Configuration scanning          │
└────────────────┬─────────────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────────────┐
│                  OPERATE                             │
│  Runtime security, Monitoring, Incident response     │
└────────────────┬─────────────────────────────────────┘
                 │
                 └─────────────┐
                               │
┌──────────────────────────────▼───────────────────────┐
│                   MONITOR                            │
│  SIEM, Log analysis, Threat detection                │
└──────────────────────────────────────────────────────┘
```

---

## CI/CD Pipeline Fundamentals

### What is CI/CD?

**Continuous Integration (CI)**: Automatically build and test code changes
**Continuous Delivery (CD)**: Automatically prepare releases
**Continuous Deployment**: Automatically deploy to production

### Basic CI/CD Workflow

```
Developer → Git Push → CI Server → Build → Test → Deploy
```

### Popular CI/CD Tools

- **GitHub Actions**: Integrated with GitHub
- **GitLab CI**: Integrated with GitLab
- **Jenkins**: Self-hosted, highly customizable
- **CircleCI**: Cloud-based
- **Travis CI**: Cloud-based
- **Azure DevOps**: Microsoft ecosystem

---

## Version Control and Git Workflows

### Git Best Practices

```bash
# Clone repository
git clone https://github.com/user/repo.git
cd repo

# Create feature branch
git checkout -b feature/add-authentication

# Make changes and commit
git add .
git commit -m "feat: add JWT authentication"

# Push to remote
git push origin feature/add-authentication

# Create pull request (via GitHub/GitLab UI)
```

### Git Workflow Strategies

**1. Git Flow**:
```
main (production)
  ├── develop (development)
  │     ├── feature/feature-1
  │     ├── feature/feature-2
  │     └── feature/feature-3
  └── hotfix/critical-bug
```

**2. GitHub Flow** (simpler):
```
main (production)
  ├── feature/feature-1
  ├── feature/feature-2
  └── bugfix/fix-login
```

**3. Trunk-Based Development**:
```
main (always deployable)
  ├── short-lived feature branch
  └── short-lived feature branch
```

### Commit Message Conventions

```bash
# Conventional Commits
feat: add user authentication
fix: resolve login redirect issue
docs: update API documentation
style: format code with prettier
refactor: simplify database queries
test: add unit tests for auth module
chore: update dependencies
```

### Pre-commit Hooks

**Setup**:
```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml <<EOF
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-json
      - id: detect-private-key

  - repo: https://github.com/pre-commit/mirrors-eslint
    rev: v8.56.0
    hooks:
      - id: eslint
        files: \\.js$

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
EOF

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

### Protecting Secrets

```bash
# Never commit these files
cat >> .gitignore <<EOF
.env
.env.local
.env.production
*.pem
*.key
config/secrets.yml
credentials.json
EOF

# Check for secrets before commit
git diff --cached | grep -i "password\|secret\|api_key"

# Use git-secrets
git secrets --install
git secrets --register-aws
```

---

## Container Security

### Docker Security Best Practices

**1. Use Official Base Images**:
```dockerfile
# Good: Official Node.js image
FROM node:20-alpine

# Bad: Random image from unknown source
FROM randomuser/node:latest
```

**2. Run as Non-Root User**:
```dockerfile
FROM node:20-alpine

# Create user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set working directory
WORKDIR /app

# Copy files
COPY package*.json ./
RUN npm ci --only=production

COPY . .

# Change ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Start application
CMD ["node", "server.js"]
```

**3. Multi-Stage Builds**:
```dockerfile
# Build stage
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Production stage
FROM node:20-alpine

RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy only production dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy built application from builder
COPY --from=builder --chown=nodejs:nodejs /app/build ./build

USER nodejs
EXPOSE 3000
CMD ["node", "build/server.js"]
```

**4. Minimize Attack Surface**:
```dockerfile
# Use minimal base image
FROM node:20-alpine

# Install only necessary packages
RUN apk add --no-cache tini

# Remove unnecessary files
RUN rm -rf /tmp/* /var/cache/apk/*

# Don't include development dependencies
RUN npm ci --only=production && \
    npm cache clean --force
```

**5. Scan for Vulnerabilities**:
```bash
# Trivy (container scanner)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image myapp:latest

# Snyk
snyk container test myapp:latest

# Docker Scout
docker scout cves myapp:latest
```

### Docker Compose Security

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    env_file:
      - .env.production
    networks:
      - app-network
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - ./logs:/app/logs:rw

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
    secrets:
      - db_password
    networks:
      - app-network
    volumes:
      - db-data:/var/lib/postgresql/data

networks:
  app-network:
    driver: bridge

volumes:
  db-data:

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

---

## Infrastructure as Code (IaC)

### What is IaC?

Managing infrastructure through code instead of manual configuration.

**Benefits**:
- Version control for infrastructure
- Reproducible environments
- Automated deployments
- Documentation as code

### Terraform Example

**Provider Configuration** (`main.tf`):
```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "main-vpc"
    Environment = var.environment
  }
}

# Subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet"
  }
}

# Security Group
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "web-security-group"
  }
}

# EC2 Instance
resource "aws_instance" "web" {
  ami           = var.ami_id
  instance_type = var.instance_type
  subnet_id     = aws_subnet.public.id

  vpc_security_group_ids = [aws_security_group.web.id]

  user_data = file("user-data.sh")

  tags = {
    Name        = "web-server"
    Environment = var.environment
  }
}
```

**Variables** (`variables.tf`):
```hcl
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "ami_id" {
  description = "AMI ID for EC2 instance"
  type        = string
}
```

**Usage**:
```bash
# Initialize Terraform
terraform init

# Plan changes
terraform plan

# Apply changes
terraform apply

# Destroy infrastructure
terraform destroy
```

### IaC Security Scanning

```bash
# tfsec - Terraform security scanner
tfsec .

# Checkov - Multi-cloud IaC scanner
checkov -d .

# Terrascan
terrascan scan -t aws

# Example tfsec output:
# CRITICAL: Security group allows ingress from 0.0.0.0/0 to port 22
# Fix: Restrict SSH access to specific IPs
```

---

## Security Testing Automation

### Types of Security Testing

```
┌─────────────────────────────────────────────┐
│  SAST (Static Application Security Testing)│
│  - Analyze source code                      │
│  - Find vulnerabilities before runtime      │
│  - Tools: SonarQube, Semgrep, CodeQL        │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│  DAST (Dynamic Application Security Testing)│
│  - Test running application                 │
│  - Black-box testing                        │
│  - Tools: OWASP ZAP, Burp Suite             │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│  SCA (Software Composition Analysis)        │
│  - Scan dependencies for vulnerabilities    │
│  - Check licenses                           │
│  - Tools: Snyk, npm audit, Dependabot       │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│  Container Scanning                         │
│  - Scan container images                    │
│  - Check for CVEs                           │
│  - Tools: Trivy, Clair, Anchore             │
└─────────────────────────────────────────────┘
```

### Dependency Scanning

```bash
# npm audit
npm audit
npm audit fix
npm audit fix --force

# Check specific package
npm view package-name versions
npm outdated

# Snyk
npm install -g snyk
snyk auth
snyk test
snyk monitor

# OWASP Dependency-Check
dependency-check --project myapp --scan .

# GitHub Dependabot
# Automatically creates PRs for vulnerable dependencies
```

### SAST Example with Semgrep

**Install**:
```bash
pip install semgrep
```

**Run**:
```bash
# Run with default rules
semgrep --config=auto .

# Run specific rulesets
semgrep --config=p/security-audit .
semgrep --config=p/owasp-top-ten .

# Output to JSON
semgrep --config=auto --json -o results.json .
```

**Custom Rules** (`.semgrep.yml`):
```yaml
rules:
  - id: hardcoded-secret
    pattern: |
      const $VAR = "$SECRET"
    message: Potential hardcoded secret
    severity: ERROR
    languages:
      - javascript
      - typescript

  - id: sql-injection
    pattern: |
      db.query(`SELECT * FROM users WHERE id = ${$USER_INPUT}`)
    message: Potential SQL injection
    severity: ERROR
    languages:
      - javascript
```

---

## Secrets Management

### Never Hardcode Secrets

```javascript
// BAD - Hardcoded secrets
const API_KEY = "sk-1234567890abcdef";
const DB_PASSWORD = "MyP@ssw0rd";

// GOOD - Environment variables
const API_KEY = process.env.API_KEY;
const DB_PASSWORD = process.env.DB_PASSWORD;
```

### Environment Variables

**.env file**:
```bash
NODE_ENV=production
DATABASE_URL=postgresql://user:password@localhost:5432/mydb
API_KEY=your-api-key
JWT_SECRET=your-jwt-secret
```

**Load in application**:
```javascript
// Using dotenv
require('dotenv').config();

const dbUrl = process.env.DATABASE_URL;
const apiKey = process.env.API_KEY;
```

**Never commit .env**:
```bash
# .gitignore
.env
.env.local
.env.production
.env.*.local
```

### HashiCorp Vault

**Start Vault** (development):
```bash
# Start Vault server
vault server -dev

# Set environment variable
export VAULT_ADDR='http://127.0.0.1:8200'

# Authenticate
vault login <root_token>

# Store secret
vault kv put secret/myapp/db password=MySecretPassword

# Retrieve secret
vault kv get secret/myapp/db

# Get specific field
vault kv get -field=password secret/myapp/db
```

**Use in Application**:
```javascript
const vault = require('node-vault')();

async function getSecret() {
  const result = await vault.read('secret/data/myapp/db');
  const password = result.data.data.password;
  return password;
}
```

### AWS Secrets Manager

```bash
# Create secret
aws secretsmanager create-secret \
  --name myapp/db/password \
  --secret-string "MySecretPassword"

# Retrieve secret
aws secretsmanager get-secret-value \
  --secret-id myapp/db/password
```

**Use in Application**:
```javascript
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

async function getSecret(secretName) {
  const data = await secretsManager.getSecretValue({
    SecretId: secretName
  }).promise();

  return JSON.parse(data.SecretString);
}
```

### Kubernetes Secrets

```yaml
# Create secret
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
type: Opaque
data:
  username: dXNlcm5hbWU=  # base64 encoded
  password: cGFzc3dvcmQ=  # base64 encoded
```

```bash
# Create from file
kubectl create secret generic db-credentials \
  --from-literal=username=myuser \
  --from-literal=password=mypassword

# Use in Pod
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
    - name: app
      image: myapp:latest
      env:
        - name: DB_USERNAME
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: username
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
```

---

## Monitoring and Observability

### Three Pillars of Observability

```
┌────────────────┐
│     LOGS       │  What happened?
└────────────────┘

┌────────────────┐
│    METRICS     │  How much? How fast?
└────────────────┘

┌────────────────┐
│    TRACES      │  Where did it go?
└────────────────┘
```

### Logging Best Practices

```javascript
const winston = require('winston');

// Configure logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'my-app' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

// Add console in development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

// Usage
logger.info('User logged in', { userId: 123, ip: req.ip });
logger.error('Database connection failed', { error: err.message });
logger.warn('High memory usage', { usage: memoryUsage });

// Security logging
logger.warn('Failed login attempt', {
  username,
  ip: req.ip,
  timestamp: new Date()
});
```

### Prometheus Metrics

```javascript
const express = require('express');
const promClient = require('prom-client');

const app = express();

// Create metrics
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
});

const httpRequestTotal = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
});

// Middleware to track metrics
app.use((req, res, next) => {
  const start = Date.now();

  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;

    httpRequestDuration.labels(req.method, req.route?.path || req.path, res.statusCode).observe(duration);
    httpRequestTotal.labels(req.method, req.route?.path || req.path, res.statusCode).inc();
  });

  next();
});

// Expose metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', promClient.register.contentType);
  res.end(await promClient.register.metrics());
});
```

### Health Checks

```javascript
// Health check endpoint
app.get('/health', async (req, res) => {
  const health = {
    uptime: process.uptime(),
    timestamp: Date.now(),
    status: 'OK',
  };

  try {
    // Check database
    await db.ping();
    health.database = 'OK';

    // Check Redis
    await redis.ping();
    health.redis = 'OK';

    res.status(200).json(health);
  } catch (error) {
    health.status = 'ERROR';
    health.error = error.message;
    res.status(503).json(health);
  }
});

// Readiness check
app.get('/ready', async (req, res) => {
  try {
    await db.ping();
    res.status(200).send('Ready');
  } catch (error) {
    res.status(503).send('Not ready');
  }
});
```

---

## Practical CI/CD Examples

### GitHub Actions - Complete Pipeline

**.github/workflows/ci-cd.yml**:
```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  NODE_VERSION: '20'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  # Security scanning
  security:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2

      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'

  # Lint and test
  test:
    name: Test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run linter
        run: npm run lint

      - name: Run tests
        run: npm test -- --coverage

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info

      - name: Dependency vulnerability scan
        run: npm audit --audit-level=high

  # Build and push Docker image
  build:
    name: Build Docker Image
    runs-on: ubuntu-latest
    needs: [security, test]
    if: github.event_name == 'push'
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4

      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=sha,prefix={{branch}}-

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}

      - name: Scan image with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-image-results.sarif'

  # Deploy to staging
  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/develop'
    environment:
      name: staging
      url: https://staging.example.com
    steps:
      - name: Deploy to staging
        run: |
          echo "Deploying to staging..."
          # Add your deployment commands here

  # Deploy to production
  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    environment:
      name: production
      url: https://example.com
    steps:
      - name: Deploy to production
        run: |
          echo "Deploying to production..."
          # Add your deployment commands here

      - name: Notify team
        run: |
          curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
            -H 'Content-Type: application/json' \
            -d '{"text":"Deployed to production successfully"}'
```

### GitLab CI/CD

**.gitlab-ci.yml**:
```yaml
stages:
  - security
  - test
  - build
  - deploy

variables:
  NODE_VERSION: "20"
  DOCKER_DRIVER: overlay2

# Security scanning
security-scan:
  stage: security
  image: node:${NODE_VERSION}
  script:
    - npm ci
    - npm audit --audit-level=high
    - npx snyk test || true

sast:
  stage: security
  image: returntocorp/semgrep
  script:
    - semgrep --config=auto .

# Linting and testing
lint:
  stage: test
  image: node:${NODE_VERSION}
  script:
    - npm ci
    - npm run lint

test:
  stage: test
  image: node:${NODE_VERSION}
  script:
    - npm ci
    - npm test -- --coverage
  coverage: '/All files[^|]*\|[^|]*\s+([\d\.]+)/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml

# Build Docker image
build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA
  only:
    - main
    - develop

# Container scanning
container-scan:
  stage: build
  image: aquasec/trivy:latest
  script:
    - trivy image $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA

# Deploy to staging
deploy-staging:
  stage: deploy
  image: alpine:latest
  before_script:
    - apk add --no-cache openssh-client
  script:
    - echo "Deploying to staging..."
    # Add deployment commands
  environment:
    name: staging
    url: https://staging.example.com
  only:
    - develop

# Deploy to production
deploy-production:
  stage: deploy
  image: alpine:latest
  before_script:
    - apk add --no-cache openssh-client
  script:
    - echo "Deploying to production..."
    # Add deployment commands
  environment:
    name: production
    url: https://example.com
  only:
    - main
  when: manual
```

---

## Key Takeaways

1. **Shift Left**: Integrate security early
2. **Automate Everything**: Security checks, testing, deployment
3. **Continuous Monitoring**: Always watch for security issues
4. **Secrets Management**: Never hardcode secrets
5. **Container Security**: Scan images, run as non-root
6. **IaC Security**: Scan infrastructure code
7. **Fast Feedback**: Give developers quick security feedback
8. **Collaboration**: Security is everyone's responsibility

---

## Next Steps

- Set up CI/CD pipeline for your project
- Implement automated security scanning
- Practice container security
- Learn Kubernetes security
- Study cloud security (AWS/Azure/GCP)
- Implement monitoring and logging
- Practice incident response
- Get certified (AWS DevOps, CKS, etc.)

**For React/TypeScript Developers**: DevSecOps skills are crucial for modern web development. Integrate security into your workflow from day one!
