# Ultimate Certified Kubernetes Security Specialist (CKS) Preparation Guide - V1.31 (2024)


This guide is part of the [Complete CKS Certification Course]()

## CKS Exam Overview

The Certified Kubernetes Security Specialist (CKS) exam has a duration of 2 hours.
To pass the exam, candidates need to achieve a score of at least 66%.
The exam will be on Kubernetes version 1.31.
Once the certificate is earned, the CKS certification remains valid for 2 years. The cost to take the exam is $395 USD.

<!-- >**Important Note:** The CKS exam is updating after September 15 2024, with new topics and a focus on real-world Kubernetes skills like Gateway API, Helm, Kustomize, CRDs & Operators. This guide is based on the new CKA syllabus. You can read more about the exam changes here [CKS Exam Changes](https://blog.techiescamp.com/cka-exam-updates/) -->


## Table of Contents

1. [Cluster Setup (15%)](#)
   - [Use Network security policies to restrict cluster level access](#)
   - [Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)](#)
   - [Properly set up Ingress with TLS](#)
   - [Protect node metadata and endpoints](#)
   - [Verify platform binaries before deploying](#)

2. [Cluster Hardening (15%)](#)
   - [Use Role Based Access Controls to minimize exposure](#)
   - [Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones](#)
   - [Restrict access to Kubernetes API](#)
   - [Upgrade Kubernetes to avoid vulnerabilities](#)

3. [System Hardening (10%)](#)
   - [Minimize host OS footprint (reduce attack surface)](#)
   - [Using least-privilege identity and access management](#)
   - [Minimize external access to the network](#)
   - [Appropriately use kernel hardening tools such as AppArmor, seccomp](#)

4. [Minimize Microservice Vulnerabilities (20%)](#)
   - [Use appropriate pod security standards](#)
   - [Manage Kubernetes secrets](#)
   - [Understand and implement isolation techniques (multi-tenancy, sandboxed containers, etc.)](#)
   - [Implement Pod-to-Pod encryption using Cilium](#)

5. [Troubleshooting (30%)](#5-troubleshooting-30)
   - [Troubleshoot clusters and nodes](#troubleshoot-clusters-and-nodes)
   - [Troubleshoot cluster components](#troubleshoot-cluster-components)
   - [Monitor cluster and application resource usage](#monitor-cluster-and-application-resource-usage)
   - [Manage and evaluate container output streams](#manage-and-evaluate-container-output-streams)
   - [Troubleshoot services and networking](#troubleshoot-services-and-networking)

## CKS Exam Detailed Study Guide & References

CKs Certification Exam has the following key domains:

## 1. Cluster Setup (15%)

Following are the subtopics under Cluster Setup

### Network Policy
> [Network Policy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)  : Understand the restriction of the Pod to Pod communication.

```yaml
# Create a Deny all Network Policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

```yaml
# Protecting Metadata Server access to the cloud provider Kubernetes cluster using Network Policy

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: metadata-network-policy
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32
```
### CIS Benchmark
> [CIS Benchmark]() : Analyze the cluster components using CIS Benchmark tool Kube Bench.
```bash
# CIS Benchmark Best Practices
./kube-bench --config-dir /root/cfg --config /root/cfg/config.yaml
```
```bash
# Analyze the benchmark of specific check
./kube-bench --config-dir /root/cfg --config /root/cfg/config.yaml --check 1.4.1
```

### Ingress 
> [Ingress]() : Creating an Ingress object with the TLS termination.
```bash
# Self-signed TLS Certificate & Key
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout tls.key -out tls.crt
```
```bash
# Create a TLS secret with Certificat & Key
kubectl -n tls create secret tls tls-secret --cert=tls.crt --key=tls.key
```
```yaml
# Create Ingress with TLS
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-ingress
  namespace: tls
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
	tls:
  - hosts:
      - dev.techiescamp.com
    secretName: tls-secret
  rules:
  - host: dev.techiescamp.com
    http:
      paths:
      - path: /app
        pathType: Prefix
        backend:
          service:
            name: app
            port:
              number: 80
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api
            port:
              number: 80

```
### Verify Kubernetes Platform Binaries

```bash
# Verify the Platform Binaries using Hash

kubectl --version

sha512sum $(which kubectl)

wget https://dl.k8s.io/v1.31.0/kubernetes-server-linux-amd64.tar.gz

tar -xvf kubernetes-server-linux-amd64.tar.gz

sha512sum kubernetes/server/bin/kubelet
```

## 2. Cluster Hardening (15%)

### RBAC, Certificate & Certificate Signing Request

```bash
# Create private key
openssl genrsa -out myuser.key 2048
openssl req -new -key myuser.key -out myuser.csr -subj "/CN=myuser"

# Create Certificate Signing Request (CSR)
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: myuser
spec:
  request: 
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400  # one day
  usages:
  - client auth

# Copy base64 encoded CSR file content
cat myuser.csr | base64 | tr -d "\n"

# Paste the content to `spec.request`
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: myuser
spec:
  request: <base64 encoded csr content>
  signerName: kubernetes.io/kube-apiserver-client
  expirationSeconds: 86400  # one day
  usages:
  - client auth

# Apply the CSR manifest
kubectl apply -f csr.yaml

# Get the list of CSR
kubectl get csr

# Approve the CSR
kubectl certificate approve myuser

# Export the certificate
kubectl get csr myuser -o jsonpath='{.status.certificate}'| base64 -d > myuser.crt

# Create Role
kubectl create role developer --verb=create --verb=get --verb=list --verb=update --verb=delete --resource=pods

# Create Role Binding
kubectl create rolebinding developer-binding-myuser --role=developer --user=myuser

# Test the role to the user
kubectl auth can-i delete pods --as myuser
kubectl auth can-i delete deployments --as myuser

# Add new credentials
kubectl config set-credentials myuser --client-key=myuser.key --client-certificate=myuser.crt --embed-certs=true

# Add context
kubectl config set-context myuser --cluster=kubernetes --user=myuser

# List contexts
kubectl config get-context

# Change context
kubectl config use-context myuser
```

### Role Based Access Control 
> Bind RBAC with Service Account 
```bash
# Create SA
kubectl create sa app-sa

# Create Cluster Role
kubectl create clusterrole app-cr --verb list --resource pods

# Create Role Binding
kubectl create rolebinding app-rb --clusterrole app-cr --serviceaccount default:app-sa

# List Role Binding
kubectl get rolebinding

# Describe Role Binding
kubectl describe rolebinding app-rb

# Check the access
kubectl auth can-i list pods --as system:serviceaccount:default:app-sa

# Create a Pod with the Service Account
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: app-sa
  name: app-sa
spec:
  serviceAccountName: app-sa
  containers:
  - image: nginx
    name: app-sa
    ports:
    - containerPort: 80
```
### Service Account Token Automount
> [Service Account](#https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/) : Disable the automounting of the Service Account Token. 
```bash
# Disable Service Account Token Automounting
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: app-sa
  name: app-sa
spec:
  serviceAccountName: app-sa
  automountServiceAccountToken: false
  containers:
  - image: nginx
    name: app-sa
    ports:
    - containerPort: 80
```
### Upgrade Kubernetes clusters.
> [Perform Cluster Version upgrade Using Kubeadm](https://techiescamp.com/courses/certified-kubernetes-administrator-course/lectures/55120133) : Managing the lifecycle involves upgrading clusters, managing control plane nodes, and ensuring consistency across versions.

## 3. System Hardening (10%)
### Disable Service
```bash
# Stop a running service
systemctl stop vsftpd

# Check the status of the service
systemctl status vsftpd
```
### Remove Unused Packages
```bash
# Remove the packages
sudo apt remove vsftpd
```
### Disable Open Ports 
```bash
# Identify open ports and related processes
ss -tlpn

# Filter a process using the open port number
ss -tlpn | grep :80
```

### Kernel Hardening using AppArmor
```bash
# To list the default and custom loaded profiles
aa-status

# Profile modes - 'enforce' and `complain'
# Example profile file which is restrict the write function to nodes
#include <tunables/global>

profile k8s-apparmor-example-deny-write flags=(attach_disconnected) {
  #include <abstractions/base>

  file,

  # Deny all file writes.
  deny /** w,
}

# To load the profile ('enforce' mode is default)

apparmor_parser /etc/apparmor.d/k8s-apparmor-example-deny-write

# Associate the profile to a Pod
apiVersion: v1
kind: Pod
metadata:
  name: hello-apparmor
spec:
  securityContext:
    appArmorProfile:
      type: Localhost
      localhostProfile: k8s-apparmor-example-deny-write
  containers:
  - name: hello
    image: busybox:1.28
    command: [ "sh", "-c", "echo 'Hello AppArmor!' && sleep 1h" ]

```
> Note: The profiles should be present in the worker nodes or where the workloads should be in.

## 4. Minimize Microservice Vulnerabilities (20%)
### Run Container as Non-Root User 
```bash
# Adding security context to run the container as non root user
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: test-pod
  name: test-pod
spec:
  containers:
  - image: bitnami/nginx
    name: test-pod
  securityContext:
    runAsNonRoot: true
```

### Run a Container with Specific User ID and Group ID 
```bash
# Run container with specific user id and group id
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: test-pod
  name: test-pod
spec:
  containers:
  - image: busybox
    name: test-pod
    command: ["sh", "-c", "sleep 1d"]
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
```
### Non Privileged Container 
```bash
#
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  containers:
  - name: sec-ctx-demo
    image: busybox:1.28
    command: [ "sh", "-c", "sleep 1h" ]
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
```
### Pod Security Admission
```bash
# Add label to the namespace for the PSA
k label namespace dev pod-security.kubernetes.io/enforce=restricted

# Enable Pod Security Admission Plugin in the Kube Apiserver
vim /etc/kubernetes/manifests/kube-apiserver

- --enable-admission-plugins=podSecurity
```
### ECTD encryption
```bash
# Create a randon base64 encoded key
echo -n "encryptedsecret" | base64

# Create an Encryption configuration file with the encoded key
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - identity: {}
      - aesgcm:
          keys:
            - name: key1
              secret: ZW5jcnlwdGVkc2VjcmV0

# Add Encryption Provider Config parameter and volumes on the Kube Api server

--encryption-provider-config=/etc/kubernetes/etcd/ec.yaml

spec
  volumes:
  - name: ec
    hostPath: 
      path: /etc/kubernetes/etcd
      type: DirectoryOrCreate

  containers:
    volumemounts:
    - name: ec
      mountPath: /etc/kubernetes/etcd
      readonly: true

# Wait to the Kube API server to restart
watch crictl ps

# Replace the secret
kubectl get secret test-secret -o json | kubectl replace -f -

# Check the encrypted secret 
ETCDCTL_API=3 etcdctl \
   --cacert=/etc/kubernetes/pki/etcd/ca.crt   \
   --cert=/etc/kubernetes/pki/etcd/server.crt \
   --key=/etc/kubernetes/pki/etcd/server.key  \
   get /registry/secrets/default/test-secret | hexdump -C
```
### Container Runtime sandboxed
```bash
# Create a Runtime Class - gVisor
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc

# Create a Pod with Runtime Class
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: rtc-pod
  name: rtc-pod
spec:
  runtimeClassName: gvisor
  containers:
  - image: nginx
    name: rtc-pod
    ports:
    - containerPort: 80

# To check the container runtime
k exec rtc-pod -- dmesg
bash

