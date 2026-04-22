# eleVADR Docker & Kubernetes Guide

This guide provides detailed instructions for containerizing and deploying eleVADR using Docker and Kubernetes.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Docker Setup](#docker-setup)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Scaling Strategies](#scaling-strategies)
- [Production Considerations](#production-considerations)
- [Troubleshooting](#troubleshooting)

## Architecture Overview

### Container Structure

The eleVADR container includes:
- **Ubuntu 22.04** base image
- **Zeek Network Security Monitor** (compiled and installed)
- **Python 3.10** with all required dependencies
- **Analysis engine** (eleVADR application code)
- **Entrypoint script** for automated PCAP processing

### Data Flow

```
PCAP Input (mounted volume)
    ↓
Container starts → Entrypoint script
    ↓
Copy PCAP to processing directory
    ↓
Run Zeek analysis
    ↓
Parse Zeek logs with pandas
    ↓
Generate security report
    ↓
Output JSON report (mounted volume)
```

## Docker Setup

### Building the Image

The Dockerfile uses a multi-stage build for optimization:

```bash
# Basic build
docker build -t elevadr:latest .

# Build with specific tag
docker build -t elevadr:v1.0.0 .

# Build with build arguments (if needed)
docker build --build-arg ZEEK_VERSION=5.0 -t elevadr:latest .
```

### Running Containers

#### Basic Usage

```bash
# Single PCAP analysis
docker run --rm \
  -v /path/to/pcaps:/input:ro \
  -v /path/to/reports:/output \
  elevadr:latest
```

#### Advanced Options

```bash
# Custom PCAP filename
docker run --rm \
  -v /path/to/pcaps:/input:ro \
  -v /path/to/reports:/output \
  -e PCAP_INPUT=/input/myfile.pcap \
  -e REPORT_OUTPUT=/output/myreport.json \
  elevadr:latest

# Resource limits
docker run --rm \
  -v /path/to/pcaps:/input:ro \
  -v /path/to/reports:/output \
  --memory="4g" \
  --cpus="2" \
  elevadr:latest

# Custom reference data
docker run --rm \
  -v /path/to/pcaps:/input:ro \
  -v /path/to/reports:/output \
  -v /path/to/custom-data:/app/app/data/assessor_data:ro \
  elevadr:latest
```

### Docker Compose

The included `docker-compose.yml` provides two services:

1. **elevadr**: Main analysis service
2. **report-server**: Optional Nginx server for viewing reports

```bash
# Run analysis only
docker-compose up elevadr

# Run analysis and start web server
docker-compose --profile web-server up

# Run in background
docker-compose up -d elevadr

# View logs
docker-compose logs -f elevadr

# Clean up
docker-compose down -v
```

### Volume Management

#### Input Volume (`/input`)
- Mount as **read-only** (`:ro`)
- Contains PCAP files to analyze
- Default expects `capture.pcap`

#### Output Volume (`/output`)
- Mount as **read-write**
- Receives JSON reports
- Persists analysis results

#### Custom Data Volume (optional)
- Mount custom reference data
- Path: `/app/app/data/assessor_data`
- Include: `ports.json`, `port_risk.json`, `latest_oui_lookup.json`, `CONST.yml`

## Kubernetes Deployment

### Architecture

The Kubernetes deployment includes:

- **Namespace**: `elevadr` (isolated environment)
- **ConfigMap**: Environment configuration
- **PersistentVolumeClaims**: Storage for PCAPs and reports
- **Jobs**: One-time PCAP analysis tasks
- **CronJobs**: Scheduled recurring analysis

### Prerequisites

1. **Kubernetes Cluster**
   - Local: minikube, kind, Docker Desktop
   - Cloud: GKE, EKS, AKS

2. **kubectl** installed and configured

3. **Container Registry** access
   - Docker Hub: `docker.io/username`
   - Google Container Registry: `gcr.io/project`
   - Amazon ECR: `account.dkr.ecr.region.amazonaws.com`

### Initial Deployment

#### Step 1: Prepare the Image

```bash
# Build
docker build -t elevadr:latest .

# Tag for registry
docker tag elevadr:latest your-registry/elevadr:latest

# Push
docker push your-registry/elevadr:latest
```

#### Step 2: Update Configuration

Edit `k8s/kustomization.yaml`:

```yaml
images:
  - name: elevadr
    newName: your-registry/elevadr  # Update this
    newTag: latest                   # Update this
```

#### Step 3: Deploy

```bash
# Deploy all resources
kubectl apply -k k8s/

# Verify deployment
kubectl get all -n elevadr

# Expected output:
# - namespace/elevadr
# - configmap/elevadr-config
# - persistentvolumeclaim/elevadr-pcap-input
# - persistentvolumeclaim/elevadr-report-output
# - job/elevadr-analysis
```

### Working with Jobs

#### Manual Job Execution

```bash
# Create a job
kubectl create job -n elevadr manual-analysis-1 \
  --image=your-registry/elevadr:latest

# Monitor job
kubectl get jobs -n elevadr
kubectl describe job -n elevadr manual-analysis-1

# View logs
kubectl logs -n elevadr job/manual-analysis-1 -f

# Delete completed job
kubectl delete job -n elevadr manual-analysis-1
```

#### Uploading PCAPs

**Method 1: Direct Copy to PVC**

```bash
# Find a running pod (or create temporary one)
kubectl run -n elevadr uploader --image=busybox --restart=Never -- sleep 3600

# Copy PCAP
kubectl cp /local/path/capture.pcap elevadr/uploader:/input/

# Clean up
kubectl delete pod -n elevadr uploader
```

**Method 2: Using a Helper Pod**

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pcap-loader
  namespace: elevadr
spec:
  containers:
  - name: loader
    image: busybox
    command: ['sleep', '3600']
    volumeMounts:
    - name: pcap-input
      mountPath: /input
  volumes:
  - name: pcap-input
    persistentVolumeClaim:
      claimName: elevadr-pcap-input
```

```bash
kubectl apply -f loader-pod.yaml
kubectl cp capture.pcap elevadr/pcap-loader:/input/
```

**Method 3: ConfigMap (Small PCAPs)**

```bash
kubectl create configmap -n elevadr my-pcap \
  --from-file=capture.pcap=./myfile.pcap
```

Then modify the job to mount the ConfigMap instead of PVC.

#### Retrieving Reports

```bash
# Find the job pod
POD=$(kubectl get pods -n elevadr -l job-name=elevadr-analysis -o jsonpath='{.items[0].metadata.name}')

# Copy report locally
kubectl cp elevadr/$POD:/output/report.json ./report.json

# Or view directly
kubectl exec -n elevadr $POD -- cat /output/report.json
```

### Scheduled Analysis (CronJob)

Enable scheduled analysis by uncommenting in `k8s/kustomization.yaml`:

```yaml
resources:
  - cronjob.yaml
```

The CronJob runs daily at 2 AM by default. Modify the schedule in `k8s/cronjob.yaml`:

```yaml
spec:
  schedule: "0 2 * * *"  # Cron syntax
```

Examples:
- Every hour: `"0 * * * *"`
- Every 6 hours: `"0 */6 * * *"`
- Weekly on Sunday: `"0 2 * * 0"`
- Monthly on 1st: `"0 2 1 * *"`

## Scaling Strategies

### Horizontal Scaling (Multiple Jobs in Parallel)

#### Option 1: Job Parallelism

Modify `k8s/job.yaml`:

```yaml
spec:
  parallelism: 5      # Number of pods running simultaneously
  completions: 10     # Total number of successful completions needed
```

This creates 10 jobs, running 5 at a time.

#### Option 2: Multiple Independent Jobs

Process multiple PCAPs by creating individual jobs:

```bash
#!/bin/bash
# Script: batch-analyze.sh

for pcap in /path/to/pcaps/*.pcap; do
  filename=$(basename "$pcap" .pcap)

  # Create job from template
  cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: analysis-$filename
  namespace: elevadr
spec:
  template:
    spec:
      containers:
      - name: elevadr
        image: your-registry/elevadr:latest
        env:
        - name: PCAP_INPUT
          value: /input/$filename.pcap
        - name: REPORT_OUTPUT
          value: /output/report-$filename.json
        volumeMounts:
        - name: pcap-input
          mountPath: /input
        - name: report-output
          mountPath: /output
      volumes:
      - name: pcap-input
        persistentVolumeClaim:
          claimName: elevadr-pcap-input
      - name: report-output
        persistentVolumeClaim:
          claimName: elevadr-report-output
      restartPolicy: OnFailure
EOF
done
```

### Vertical Scaling (Resource Allocation)

Adjust resources based on PCAP size:

| PCAP Size | Memory Request | Memory Limit | CPU Request | CPU Limit |
|-----------|----------------|--------------|-------------|-----------|
| < 100MB   | 1Gi            | 2Gi          | 500m        | 1000m     |
| 100MB-1GB | 2Gi            | 4Gi          | 1000m       | 2000m     |
| 1GB-5GB   | 4Gi            | 8Gi          | 2000m       | 4000m     |
| > 5GB     | 8Gi            | 16Gi         | 4000m       | 8000m     |

Update in `k8s/job.yaml`:

```yaml
resources:
  requests:
    memory: "4Gi"
    cpu: "2000m"
  limits:
    memory: "8Gi"
    cpu: "4000m"
```

### Auto-Scaling with HPA (Advanced)

For API-based deployments, use Horizontal Pod Autoscaler:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: elevadr-hpa
  namespace: elevadr
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: elevadr-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Production Considerations

### Security

1. **Run as non-root user**

Update Dockerfile:

```dockerfile
RUN useradd -m -u 1000 elevadr
USER elevadr
```

2. **Security Context in Kubernetes**

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL
```

3. **Network Policies**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: elevadr-network-policy
  namespace: elevadr
spec:
  podSelector:
    matchLabels:
      app: elevadr
  policyTypes:
  - Ingress
  - Egress
  egress:
  - to:
    - namespaceSelector: {}
```

### Monitoring

#### Prometheus Metrics

Add annotations to jobs:

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
```

#### Logging

View logs with labels:

```bash
# All elevadr logs
kubectl logs -n elevadr -l app=elevadr --tail=100

# Follow logs
kubectl logs -n elevadr -l app=elevadr -f

# Export logs
kubectl logs -n elevadr job/elevadr-analysis > analysis.log
```

### Storage Optimization

1. **Use Storage Classes**

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: elevadr-pcap-input
spec:
  storageClassName: fast-ssd  # Use SSD for better performance
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 100Gi
```

2. **Lifecycle Policies**

Automatically clean old reports:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cleanup-old-reports
spec:
  schedule: "0 3 * * 0"  # Weekly
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: cleanup
            image: busybox
            command:
            - sh
            - -c
            - find /output -name "*.json" -mtime +30 -delete
            volumeMounts:
            - name: reports
              mountPath: /output
          volumes:
          - name: reports
            persistentVolumeClaim:
              claimName: elevadr-report-output
```

### High Availability

1. **Multiple Replicas** (for API deployments)
2. **Pod Disruption Budgets**
3. **Node Affinity** for resource-intensive nodes

```yaml
affinity:
  nodeAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      preference:
        matchExpressions:
        - key: workload
          operator: In
          values:
          - analysis
```

## Troubleshooting

### Common Issues

#### 1. PCAP Not Found

**Symptom**: Error: PCAP file not found at /input/capture.pcap

**Solution**:
- Verify volume mount: `kubectl describe pod -n elevadr <pod-name>`
- Check PVC status: `kubectl get pvc -n elevadr`
- Ensure PCAP was uploaded correctly

#### 2. Out of Memory

**Symptom**: Pod killed with OOMKilled status

**Solution**:
```bash
# Check pod status
kubectl get pods -n elevadr

# Increase memory limits in k8s/job.yaml
resources:
  limits:
    memory: "8Gi"  # Increase this
```

#### 3. Zeek Not Found

**Symptom**: Error: Zeek is not installed or not in PATH

**Solution**:
- Rebuild Docker image
- Verify Zeek installation in Dockerfile
- Check PATH environment variable

#### 4. Permission Denied

**Symptom**: Cannot write to /output

**Solution**:
```yaml
# Add securityContext
securityContext:
  fsGroup: 1000
```

#### 5. Job Not Starting

**Symptom**: Job remains in pending state

**Solution**:
```bash
# Check job status
kubectl describe job -n elevadr elevadr-analysis

# Common causes:
# - Insufficient cluster resources
# - Image pull errors
# - PVC binding issues

# Check events
kubectl get events -n elevadr --sort-by='.lastTimestamp'
```

### Debug Commands

```bash
# Get detailed pod information
kubectl describe pod -n elevadr <pod-name>

# Shell into running container
kubectl exec -it -n elevadr <pod-name> -- /bin/bash

# Check resource usage
kubectl top pods -n elevadr

# View all events
kubectl get events -n elevadr --sort-by='.lastTimestamp'

# Get job YAML
kubectl get job -n elevadr elevadr-analysis -o yaml

# Test entrypoint script
kubectl exec -n elevadr <pod-name> -- cat /usr/local/bin/docker-entrypoint.sh
```

### Performance Tuning

1. **Optimize Zeek Processing**
   - Reduce packet capture filters
   - Disable unnecessary Zeek scripts

2. **Pandas Optimization**
   - Use chunking for large datasets
   - Enable parallel processing

3. **Storage I/O**
   - Use SSD-backed storage
   - Enable caching
   - Use local volumes for temporary data

## Additional Resources

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [Zeek Documentation](https://docs.zeek.org/)
- [eleVADR Main README](README.md)
