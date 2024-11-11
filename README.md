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

3. [Storage (10%)](#3-storage-10)
   - [Implement storage classes and dynamic volume provisioning](#implement-storage-classes-and-dynamic-volume-provisioning)
   - [Configure volume types, access modes and reclaim policies](#configure-volume-types-access-modes-and-reclaim-policies)
   - [Manage persistent volumes and persistent volume claims](#manage-persistent-volumes-and-persistent-volume-claims)

4. [Services & Networking (20%)](#4-services--networking-20)
   - [Understand connectivity between Pods](#understand-connectivity-between-pods)
   - [Define and enforce Network Policies](#define-and-enforce-network-policies)
   - [Use ClusterIP, NodePort, LoadBalancer service types and endpoints](#use-clusterip-nodeport-loadbalancer-service-types-and-endpoints)
   - [Use the Gateway API to manage Ingress traffic](#use-the-gateway-api-to-manage-ingress-traffic)
   - [Know how to use Ingress controllers and Ingress resources](#know-how-to-use-ingress-controllers-and-ingress-resources)
   - [Understand and use CoreDNS](#understand-and-use-coredns)

5. [Troubleshooting (30%)](#5-troubleshooting-30)
   - [Troubleshoot clusters and nodes](#troubleshoot-clusters-and-nodes)
   - [Troubleshoot cluster components](#troubleshoot-cluster-components)
   - [Monitor cluster and application resource usage](#monitor-cluster-and-application-resource-usage)
   - [Manage and evaluate container output streams](#manage-and-evaluate-container-output-streams)
   - [Troubleshoot services and networking](#troubleshoot-services-and-networking)

## CKs Exam Detailed Study Guide & References

CKs Certification Exam has the following key domains:

## 1. Cluster Setup (15%)

Following are the subtopics under Cluster Setup

### Network Policy.
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
### Analyze the cluster components using CIS Benchmark tool Kube Bench.
```bash
# CIS Benchmark Best Practices
./kube-bench --config-dir /root/cfg --config /root/cfg/config.yaml
```
```bash
# Analyze the benchmark of specific check
./kube-bench --config-dir /root/cfg --config /root/cfg/config.yaml --check 1.4.1
```

### Ingress object with TLS 
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



