---
title: "Kubernetes統合 ― クラウドネイティブ時代のネットワーク解析"
---

# Kubernetes統合

## 本章の目的

StratoSharkのKubernetes統合機能を活用した、クラウドネイティブ環境でのネットワーク解析手法を学びます。Pod単位のキャプチャ、Service Mesh解析、CNI統合、NetworkPolicy検証など、Kubernetes特有の課題に対応する実践的なテクニックを解説します。

## Kubernetes環境の特徴

### 従来のネットワーク解析との違い

**従来の環境**:
```
Host A ←→ Host B
  ↓          ↓
 eth0       eth0
```

**Kubernetes環境**:
```
Node A                           Node B
  ├─ Pod 1 (veth0)                ├─ Pod 3 (veth0)
  │  └─ Container 1a              │  └─ Container 3a
  │     └─ Container 1b           │     └─ Container 3b
  ├─ Pod 2 (veth1)                ├─ Pod 4 (veth1)
  │  └─ Container 2a              │  └─ Container 4a
  └─ CNI Bridge (cni0/calico)     └─ CNI Bridge (cni0/calico)
       ↓                                ↓
     eth0 ←────── Overlay Network ─────→ eth0
       ↓                                ↓
   Service (ClusterIP)             Ingress Controller
```

**複雑性の増加**:
- 仮想ネットワークインターフェース（veth pair）
- Overlay Network（VXLAN/IPIP）
- Service（ClusterIP/NodePort/LoadBalancer）
- Ingress/Egress
- Network Policy
- Service Mesh（Istio/Linkerd/Consul）

---

## StratoSharkのKubernetes対応

### eBPFによるKubernetesメタデータの取得

StratoSharkは、eBPFを使ってKubernetes固有の情報を自動的に取得します。

**取得できる情報**:
```
▼ eBPF Kubernetes Metadata
  ├─ Pod Name: nginx-deployment-7d9c8b5f4-abc12
  ├─ Namespace: production
  ├─ Container ID: a1b2c3d4e5f6
  ├─ Container Name: nginx
  ├─ Service Name: nginx-service
  ├─ Deployment: nginx-deployment
  ├─ ReplicaSet: nginx-deployment-7d9c8b5f4
  ├─ Labels:
  │  ├─ app: nginx
  │  ├─ version: v1.2.3
  │  └─ tier: frontend
  └─ Node Name: worker-node-1
```

**従来のツールとの比較**:
| ツール | Pod情報 | Container情報 | Service情報 | Labels |
|--------|---------|---------------|-------------|--------|
| **tcpdump** | ❌ | ❌ | ❌ | ❌ |
| **Wireshark** | ❌ | ❌ | ❌ | ❌ |
| **StratoShark** | ✅ | ✅ | ✅ | ✅ |

---

## DaemonSetとしてのデプロイ

### 基本的なDaemonSet構成

StratoSharkをKubernetesクラスタ全体にデプロイします。

```yaml
# stratoshark-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: stratoshark
  namespace: monitoring
  labels:
    app: stratoshark
spec:
  selector:
    matchLabels:
      app: stratoshark
  template:
    metadata:
      labels:
        app: stratoshark
    spec:
      serviceAccountName: stratoshark
      hostNetwork: true  # ホストネットワークを使用
      hostPID: true      # ホストPIDネームスペースを使用
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      - key: node-role.kubernetes.io/control-plane
        effect: NoSchedule
      containers:
      - name: stratoshark
        image: sysdig/stratoshark:latest
        securityContext:
          privileged: true  # eBPFプログラムのロードに必要
          capabilities:
            add:
            - SYS_ADMIN
            - NET_ADMIN
            - NET_RAW
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: STRATOSHARK_KUBERNETES_ENABLED
          value: "true"
        volumeMounts:
        - name: sys-kernel-debug
          mountPath: /sys/kernel/debug
        - name: sys-fs-bpf
          mountPath: /sys/fs/bpf
        - name: lib-modules
          mountPath: /lib/modules
          readOnly: true
        - name: usr-src
          mountPath: /usr/src
          readOnly: true
        - name: run-containerd
          mountPath: /run/containerd
          readOnly: true
        - name: var-lib-docker
          mountPath: /var/lib/docker
          readOnly: true
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
      volumes:
      - name: sys-kernel-debug
        hostPath:
          path: /sys/kernel/debug
      - name: sys-fs-bpf
        hostPath:
          path: /sys/fs/bpf
      - name: lib-modules
        hostPath:
          path: /lib/modules
      - name: usr-src
        hostPath:
          path: /usr/src
      - name: run-containerd
        hostPath:
          path: /run/containerd
      - name: var-lib-docker
        hostPath:
          path: /var/lib/docker
```

### RBAC設定

```yaml
# stratoshark-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: stratoshark
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: stratoshark
rules:
- apiGroups: [""]
  resources:
  - nodes
  - pods
  - services
  - endpoints
  - namespaces
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources:
  - deployments
  - replicasets
  - daemonsets
  - statefulsets
  verbs: ["get", "list", "watch"]
- apiGroups: ["networking.k8s.io"]
  resources:
  - networkpolicies
  - ingresses
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: stratoshark
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: stratoshark
subjects:
- kind: ServiceAccount
  name: stratoshark
  namespace: monitoring
```

### デプロイと確認

```bash
# Namespaceを作成
kubectl create namespace monitoring

# RBACを適用
kubectl apply -f stratoshark-rbac.yaml

# DaemonSetをデプロイ
kubectl apply -f stratoshark-daemonset.yaml

# デプロイ確認
kubectl get daemonset -n monitoring
kubectl get pods -n monitoring -o wide

# 特定ノードのStratoShark Podにアクセス
kubectl exec -it -n monitoring stratoshark-xxxxx -- bash
```

---

## Pod単位のトラフィック監視

### 特定Podのトラフィックをキャプチャ

#### 方法1: kubectl exec経由

```bash
# Pod名を取得
kubectl get pods -n production | grep nginx

# Podから直接キャプチャ（StratoSharkがPod内にある場合）
kubectl exec -n production nginx-deployment-7d9c8b5f4-abc12 -- \
  stratoshark -i any -w /tmp/capture.pcap -a duration:60

# ファイルをローカルにコピー
kubectl cp production/nginx-deployment-7d9c8b5f4-abc12:/tmp/capture.pcap ./nginx-pod.pcap

# StratoSharkで解析
stratoshark nginx-pod.pcap
```

#### 方法2: DaemonSetのStratoSharkを使用

```bash
# 対象PodのノードとIPを確認
kubectl get pod -n production nginx-deployment-7d9c8b5f4-abc12 -o wide
# NAME                                    NODE            IP
# nginx-deployment-7d9c8b5f4-abc12        worker-node-1   10.244.1.5

# そのノードで動いているStratoShark Podにアクセス
kubectl get pods -n monitoring -l app=stratoshark -o wide | grep worker-node-1
# stratoshark-xxxxx   worker-node-1

# キャプチャ実行（Pod IPでフィルタ）
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any -f "host 10.244.1.5" -w /tmp/nginx-pod.pcap -a duration:60

# ローカルにコピー
kubectl cp monitoring/stratoshark-xxxxx:/tmp/nginx-pod.pcap ./nginx-pod.pcap
```

#### 方法3: eBPFフィルタ（StratoShark独自機能）

```bash
# Pod名でフィルタ（eBPF使用）
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.pod.name == nginx-deployment-7d9c8b5f4-abc12" \
    --duration 60s \
    --output /tmp/nginx-ebpf.pcap

# ローカルにコピー
kubectl cp monitoring/stratoshark-xxxxx:/tmp/nginx-ebpf.pcap ./nginx-ebpf.pcap
```

### Pod間通信の解析

**シナリオ**: Frontend Pod → Backend Pod の通信を解析

```bash
# Frontend PodのIPを取得
FRONTEND_IP=$(kubectl get pod -n production frontend-abc123 -o jsonpath='{.status.podIP}')

# Backend PodのIPを取得
BACKEND_IP=$(kubectl get pod -n production backend-xyz789 -o jsonpath='{.status.podIP}')

# 両方のPodの通信をキャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "host $FRONTEND_IP or host $BACKEND_IP" \
    -w /tmp/pod-to-pod.pcap \
    -a duration:120

# ローカルにコピー
kubectl cp monitoring/stratoshark-xxxxx:/tmp/pod-to-pod.pcap ./pod-to-pod.pcap

# GUIで解析
stratoshark pod-to-pod.pcap
```

**GUI上でのフィルタ**:
```
# Frontend → Backend のトラフィックのみ
ip.src == <frontend-ip> && ip.dst == <backend-ip>

# eBPFメタデータでフィルタ
ebpf.k8s.pod == "frontend-abc123"
ebpf.k8s.pod == "backend-xyz789"
```

---

## Serviceの解析

### ClusterIPサービスの通信追跡

KubernetesのServiceは仮想IPであり、実際にはkube-proxyまたはeBPFがパケットを書き換えます。

**Service定義**:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: backend-service
  namespace: production
spec:
  type: ClusterIP
  selector:
    app: backend
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
```

**通信フロー**:
```
Frontend Pod (10.244.1.5)
    ↓ [Dest: backend-service:80 = 10.96.0.10:80]
kube-proxy / eBPF (DNAT)
    ↓ [Dest: backend-pod:8080 = 10.244.2.10:8080]
Backend Pod (10.244.2.10)
```

### Service経由の通信をキャプチャ

```bash
# Service IPを取得
SERVICE_IP=$(kubectl get svc -n production backend-service -o jsonpath='{.spec.clusterIP}')
echo "Service IP: $SERVICE_IP"

# Podのエンドポイントを取得
kubectl get endpoints -n production backend-service
# ENDPOINTS
# 10.244.2.10:8080,10.244.2.11:8080,10.244.2.12:8080

# キャプチャ（Service IPとPod IPsを両方含める）
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "host $SERVICE_IP or net 10.244.2.0/24" \
    -w /tmp/service-traffic.pcap \
    -a duration:60
```

### GUIでの解析

**手順**:
1. `service-traffic.pcap` を開く
2. フィルタを適用:
   ```
   ip.dst == 10.96.0.10  # Service IP
   ```
3. パケットを選択して **Follow → TCP Stream**
4. 観察:
   ```
   # リクエスト
   Source: 10.244.1.5 (Frontend Pod)
   Dest: 10.96.0.10:80 (Service ClusterIP)

   # 実際のパケット（DNAT後）
   Source: 10.244.1.5
   Dest: 10.244.2.10:8080 (Backend Pod 1)
   ```

### ロードバランシングの確認

```
# Service経由のリクエストを統計化
フィルタ: tcp.port == 8080

Statistics → Conversations → TCP
```

**結果例**:
```
Address A      Port A   Address B       Port B   Packets  Bytes
10.244.1.5     54321    10.244.2.10     8080     123      45 KB   ← 33%
10.244.1.5     54322    10.244.2.11     8080     135      47 KB   ← 33%
10.244.1.5     54323    10.244.2.12     8080     142      48 KB   ← 34%
```

→ ロードバランシングがほぼ均等（正常）

---

## Ingress/Egressトラフィックの解析

### Ingressコントローラーの監視

**Ingress定義**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  namespace: production
spec:
  ingressClassName: nginx
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend-service
            port:
              number: 80
```

**通信フロー**:
```
External Client
    ↓ [Host: app.example.com]
Ingress Controller Pod (nginx-ingress)
    ↓ [Proxy to Service]
Frontend Service (ClusterIP)
    ↓ [Load Balance]
Frontend Pods
```

### Ingressトラフィックのキャプチャ

```bash
# Ingress Controller Podを特定
kubectl get pods -n ingress-nginx -l app.kubernetes.io/component=controller

# Ingress Controller PodのIPを取得
INGRESS_IP=$(kubectl get pod -n ingress-nginx nginx-ingress-controller-abc123 \
  -o jsonpath='{.status.podIP}')

# キャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "host $INGRESS_IP and tcp port 80" \
    -w /tmp/ingress-traffic.pcap \
    -a duration:120

# ローカルにコピー
kubectl cp monitoring/stratoshark-xxxxx:/tmp/ingress-traffic.pcap ./ingress-traffic.pcap
```

### HTTPホストヘッダーの解析

```
# GUIで開く
stratoshark ingress-traffic.pcap

# フィルタ
http.host == "app.example.com"

# 統計を確認
Statistics → HTTP → Requests
```

**結果例**:
```
Host                Count    Percent
app.example.com     4,567    78.5%
api.example.com     890      15.3%
admin.example.com   234      4.0%
other               123      2.1%
```

### Egressトラフィックの監視

**ユースケース**: Podが外部API（例: api.github.com）にアクセスしているか確認

```bash
# 特定PodのEgressトラフィックをキャプチャ
POD_IP=$(kubectl get pod -n production app-pod-abc123 -o jsonpath='{.status.podIP}')

kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "src host $POD_IP and not dst net 10.0.0.0/8" \
    -w /tmp/egress-traffic.pcap \
    -a duration:60
```

**フィルタ説明**:
- `src host $POD_IP`: 対象Podからの送信
- `not dst net 10.0.0.0/8`: 宛先がクラスタ内部でない（外部）

**GUI解析**:
```
# 外部宛先を確認
Statistics → Endpoints

# HTTPSトラフィックを確認
tls.handshake.extensions_server_name
```

**結果例**:
```
Server Name                Count
api.github.com             123
api.stripe.com             45
s3.amazonaws.com           89
```

---

## Service Mesh統合

### Istio環境でのキャプチャ

IstioはSidecar ProxyとしてEnvoyを各Podに注入します。

**通信フロー**:
```
App Container (localhost:8080)
    ↓
Envoy Sidecar (localhost:15001)
    ↓ [mTLS Encrypted]
Network
    ↓
Envoy Sidecar (Target Pod)
    ↓
Target App Container
```

### Istio Sidecar Proxyのトラフィックキャプチャ

```bash
# Istio注入済みPodを特定
kubectl get pods -n production -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].name}{"\n"}{end}' | grep istio-proxy

# Podとそのノードを確認
kubectl get pod -n production app-pod-abc123 -o wide

# キャプチャ（Envoyのポートを含める）
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "host <pod-ip> and (tcp port 15001 or tcp port 15006)" \
    -w /tmp/istio-sidecar.pcap \
    -a duration:60
```

**Envoyポート**:
- **15001**: Outbound（Podからの送信）
- **15006**: Inbound（Podへの受信）
- **15020**: Health check
- **15021**: Health check（新バージョン）
- **15090**: Prometheus metrics

### mTLS通信の確認

IstioはデフォルトでmTLS（相互TLS）を使用します。

**GUIでの確認**:
```
# TLSハンドシェイクを表示
tls.handshake

# 証明書を確認
tls.handshake.certificate
```

**証明書情報例**:
```
▼ Transport Layer Security
  ▼ TLSv1.3 Record Layer: Handshake Protocol: Certificate
    ▼ Handshake Protocol: Certificate
      ▼ Certificate: spiffe://cluster.local/ns/production/sa/app
        - Subject: O=cluster.local
        - Issuer: O=cluster.local
        - SAN: URI:spiffe://cluster.local/ns/production/sa/app
        - Valid From: 2025-01-10
        - Valid Until: 2025-01-11 (24時間)
```

### Envoy統計との相関

```bash
# Envoyの統計を取得
kubectl exec -n production app-pod-abc123 -c istio-proxy -- \
  curl -s localhost:15000/stats | grep -E "(upstream_rq_|downstream_rq_)"

# StratoSharkのキャプチャと時刻を照合
# 例: upstream_rq_timeout が増加したタイミングで TCP Retransmissionを確認
```

---

## NetworkPolicyの検証

### NetworkPolicyの例

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-netpol
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
```

**期待される動作**:
- ✅ Frontend → Backend:8080 は許可
- ❌ 他のPod → Backend は拒否
- ✅ Backend → Database:5432 は許可
- ❌ Backend → 他のサービス は拒否

### NetworkPolicyのテスト

```bash
# テスト1: 許可されている通信（Frontend → Backend）
kubectl exec -n production frontend-abc123 -- \
  curl -I http://backend-service:8080
# 期待: HTTP/1.1 200 OK

# テスト2: 拒否されるべき通信（Random Pod → Backend）
kubectl run -n production test-pod --image=curlimages/curl --rm -it -- \
  curl --connect-timeout 5 http://backend-service:8080
# 期待: timeout（接続拒否）

# StratoSharkでキャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "host <backend-pod-ip>" \
    -w /tmp/netpol-test.pcap \
    -a duration:30
```

### GUIでの解析

**許可された通信**:
```
# TCP 3-way handshakeが成功
No.   Time    Source          Dest            Info
1     0.000   10.244.1.5      10.244.2.10     [SYN]
2     0.001   10.244.2.10     10.244.1.5      [SYN, ACK]
3     0.002   10.244.1.5      10.244.2.10     [ACK]
```

**拒否された通信**:
```
# SYNパケットが応答なし or RSTで拒否
No.   Time    Source          Dest            Info
1     0.000   10.244.3.5      10.244.2.10     [SYN]
2     1.000   10.244.3.5      10.244.2.10     [SYN] (Retransmission)
3     3.000   10.244.3.5      10.244.2.10     [SYN] (Retransmission)
4     7.000   10.244.3.5      10.244.2.10     [SYN] (Retransmission)
# → タイムアウト（NetworkPolicyで拒否）
```

**Expert Information**:
```
[Warn] TCP Retransmission
  → SYNパケットが再送信されている
[Note] No Response
  → サーバーから応答がない（NetworkPolicyで拒否された可能性）
```

---

## CNI統合

### Calico

CalicoはeBPFモードとiptablesモードをサポートします。

**Calico eBPFモード**:
```bash
# Calicoノードを確認
kubectl get pods -n kube-system -l k8s-app=calico-node

# eBPFモードが有効か確認
kubectl exec -n kube-system calico-node-xxxxx -- \
  calico-node -bpf enabled

# StratoSharkでキャプチャ（Calico vxlan インターフェース）
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i vxlan.calico -w /tmp/calico-vxlan.pcap -a duration:60
```

**パケット構造**:
```
▼ Ethernet II
▼ Internet Protocol Version 4
  ├─ Source: 192.168.1.10 (Node A)
  └─ Destination: 192.168.1.20 (Node B)
▼ User Datagram Protocol, Src Port: 4789, Dst Port: 4789
▼ Virtual eXtensible Local Area Network
  ├─ VNI: 4096
  ▼ Ethernet II (Inner)
    ▼ Internet Protocol Version 4 (Inner)
      ├─ Source: 10.244.1.5 (Pod A)
      └─ Destination: 10.244.2.10 (Pod B)
    ▼ TCP (Inner)
```

### Cilium

CiliumはeBPFネイティブなCNIです。

**Ciliumのモニタリング**:
```bash
# Cilium agentにアクセス
kubectl exec -n kube-system cilium-xxxxx -- cilium monitor

# StratoSharkでeBPFイベントをキャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-events cilium \
    --duration 60s \
    --output /tmp/cilium-ebpf.pcap
```

**Cilium固有情報**:
```
▼ eBPF Cilium Metadata
  ├─ Identity: 12345
  ├─ Security Identity: production:backend
  ├─ Endpoint ID: 6789
  ├─ Policy Verdict: ALLOW
  └─ Encrypted: true
```

### Flannel

FlannelはシンプルなVXLAN Overlay Networkを提供します。

**Flannelキャプチャ**:
```bash
# Flannelインターフェースを確認
kubectl exec -n monitoring stratoshark-xxxxx -- ip link show | grep flannel
# flannel.1: vxlan id 1

# キャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i flannel.1 -w /tmp/flannel-vxlan.pcap -a duration:60
```

---

## DNS解決の追跡

Kubernetes内部のDNS解決を追跡します。

### CoreDNSの監視

```bash
# CoreDNS Podを特定
kubectl get pods -n kube-system -l k8s-app=kube-dns

# CoreDNS PodのIPを取得
COREDNS_IP=$(kubectl get pod -n kube-system coredns-abc123 -o jsonpath='{.status.podIP}')

# DNSクエリをキャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "host $COREDNS_IP and udp port 53" \
    -w /tmp/coredns-queries.pcap \
    -a duration:120
```

### DNS解決の解析

**GUIでの解析**:
```
# DNSクエリを表示
フィルタ: dns

# 統計を確認
Statistics → DNS
```

**結果例**:
```
Query Name                          Count    Percent
backend-service.production.svc.cluster.local  1,234    45.2%
frontend-service.production.svc.cluster.local   890    32.6%
api-service.production.svc.cluster.local        567    20.8%
external-api.example.com                         34     1.2%
```

### DNS解決失敗の調査

```
# NXDOMAINを抽出
フィルタ: dns.flags.rcode == 3

# 例
Query: backend-svc.production.svc.cluster.local (タイポ)
Response: NXDOMAIN
```

---

## マルチクラスタ対応

### Cluster間通信の監視

**シナリオ**: Cluster A の Pod が Cluster B の Service にアクセス

**構成**:
```
Cluster A (us-west-2)
  ├─ App Pod (10.1.1.5)
  └─ Egress Gateway
      ↓ [VPN / Direct Connect]
Cluster B (us-east-1)
  ├─ Ingress Gateway
  └─ API Service (10.2.2.10)
```

### マルチクラスタトラフィックのキャプチャ

**Cluster A側**:
```bash
# Egress Gateway Podを特定
kubectl get pods -n istio-system -l istio=egressgateway

# キャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "tcp port 15443" \  # Istio mTLS port
    -w /tmp/egress-gateway.pcap \
    -a duration:120
```

**Cluster B側**:
```bash
# Ingress Gateway Podを特定
kubectl get pods -n istio-system -l istio=ingressgateway

# キャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "tcp port 15443" \
    -w /tmp/ingress-gateway.pcap \
    -a duration:120
```

### 時刻同期の確認

マルチクラスタ解析では時刻同期が重要です。

```bash
# Cluster Aのパケットタイムスタンプ
# Time: 2025-01-10 10:15:32.123456 UTC

# Cluster Bのパケットタイムスタンプ
# Time: 2025-01-10 10:15:32.125678 UTC

# → レイテンシ: 2.222 ms
```

**GUIでの比較**:
```
1. File → Merge で両方のpcapをマージ
2. View → Time Display Format → UTC Date and Time of Day
3. Flow Graphで通信フローを確認
```

---

## 実践例

### 例1: Pod間通信の高レイテンシ調査

**症状**: Frontend → Backend API呼び出しが遅い（平均1秒）

**調査手順**:

**ステップ1: 通信をキャプチャ**
```bash
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "host <frontend-ip> or host <backend-ip>" \
    -w /tmp/pod-latency.pcap \
    -a duration:120
```

**ステップ2: GUIで解析**
```
# HTTPレスポンスタイムを確認
フィルタ: http

Statistics → Service Response Time → HTTP
```

**結果**:
```
Request  Count  Min (ms)  Max (ms)  Avg (ms)
GET      123    5.2       1,234.5   987.3     ← 平均987ms
```

**ステップ3: TCP分析**
```
Statistics → TCP Stream Graphs → Round Trip Time Graph
```

**発見**: RTTは正常（10ms程度）
→ TCP自体の問題ではない

**ステップ4: eBPFメタデータを確認**
```
▼ eBPF Metadata (Backend Pod)
  ├─ Process Name: java
  ├─ CPU Usage: 95%  ← 高負荷！
  └─ Syscall Latency: 950ms  ← アプリケーション処理が遅い
```

**根本原因**: Backendアプリケーションのパフォーマンス問題（CPUボトルネック）
**解決策**: Backend Podのリソースリミットを増やす、または水平スケールする

### 例2: ServiceがPodにルーティングされない

**症状**: `curl backend-service:80` がタイムアウト

**調査手順**:

**ステップ1: Service定義を確認**
```bash
kubectl get svc -n production backend-service -o yaml
# selector:
#   app: backend
#   version: v2
```

**ステップ2: Podラベルを確認**
```bash
kubectl get pods -n production -l app=backend --show-labels
# NAME                        LABELS
# backend-deployment-abc123   app=backend,version=v1  ← version=v1（不一致！）
```

**問題発見**: SelectorとPodラベルが一致しない

**ステップ3: キャプチャで確認**
```bash
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "host <service-clusterip>" \
    -w /tmp/service-routing.pcap \
    -a duration:30
```

**ステップ4: GUIで解析**
```
フィルタ: ip.dst == <service-clusterip>

# 観察
No.   Time    Source          Dest              Info
1     0.000   10.244.1.5      10.96.0.10:80     [SYN]
2     1.000   10.244.1.5      10.96.0.10:80     [SYN] (Retransmission)
3     3.000   10.244.1.5      10.96.0.10:80     [SYN] (Retransmission)
# → DNATされていない（Endpointが空）
```

**根本原因**: Service SelectorとPodラベルの不一致
**解決策**: Podラベルを修正するか、Service Selectorを修正

### 例3: NetworkPolicyで意図しない通信がブロックされる

**症状**: Frontend → Backend API が突然動かなくなった

**調査手順**:

**ステップ1: NetworkPolicyを確認**
```bash
kubectl get networkpolicy -n production
kubectl describe networkpolicy backend-netpol -n production
```

**ステップ2: キャプチャ**
```bash
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "host <backend-pod-ip>" \
    -w /tmp/netpol-block.pcap \
    -a duration:60
```

**ステップ3: GUIで解析**
```
フィルタ: tcp.port == 8080

# 観察: SYN パケットが再送信され続ける
tcp.analysis.retransmission

# Expert Information
[Warn] TCP Retransmission
  → サーバーから応答がない
```

**ステップ4: Podラベルを確認**
```bash
kubectl get pod -n production frontend-abc123 --show-labels
# app=frontend,tier=web,env=production

# NetworkPolicyのIngressルール
# - from:
#   - podSelector:
#       matchLabels:
#         app: frontend
#         tier: frontend  ← tier=frontend が必要（不一致！）
```

**根本原因**: Frontend PodのラベルがNetworkPolicyの要件を満たしていない
**解決策**: Frontend Podに `tier=frontend` ラベルを追加

### 例4: Istio mTLS通信エラー

**症状**: App A → App B の通信が `503 Service Unavailable`

**調査手順**:

**ステップ1: Envoyログを確認**
```bash
kubectl logs -n production app-a-abc123 -c istio-proxy | tail -20
# [error] upstream connect error or disconnect/reset before headers. reset reason: connection termination
```

**ステップ2: キャプチャ**
```bash
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark -i any \
    -f "host <app-a-ip> and tcp port 15001" \
    -w /tmp/istio-mtls-error.pcap \
    -a duration:60
```

**ステップ3: GUIでTLSハンドシェイクを確認**
```
フィルタ: tls.handshake

# 観察
▼ TLSv1.3 Handshake: Client Hello
  → 送信成功

▼ TLS Alert: Certificate Expired
  → サーバー証明書が期限切れ！
```

**ステップ4: Istio証明書を確認**
```bash
kubectl exec -n production app-b-xyz789 -c istio-proxy -- \
  openssl s_client -connect localhost:15006 -showcerts </dev/null 2>/dev/null | \
  openssl x509 -noout -dates

# notAfter=Jan  9 10:00:00 2025 GMT  ← 昨日期限切れ
```

**根本原因**: Istio証明書が自動更新されていない
**解決策**: Istio Citadelを再起動して証明書を再発行

---

## パフォーマンスチューニング

### 大量トラフィック環境での最適化

**問題**: 1000+ Podを持つクラスタでパケットドロップが発生

**解決策1: バッファサイズを増やす**
```yaml
# DaemonSetの env設定
env:
- name: STRATOSHARK_BUFFER_SIZE
  value: "128M"  # デフォルト16MBから増加
```

**解決策2: フィルタを使う**
```bash
# 特定Namespaceのみキャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.namespace == production" \
    --buffer-size 64M \
    --output /tmp/production-only.pcap
```

**解決策3: ローテーション設定**
```bash
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --output /var/log/captures/traffic.pcap \
    --rotate-size 100M \
    --rotate-files 10 \
    --compress gzip
```

### リソース使用量の管理

**モニタリング**:
```bash
# StratoShark Podのリソース使用量を確認
kubectl top pod -n monitoring -l app=stratoshark

# 詳細メトリクス
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark --stats

# 出力例:
# Packets captured: 1,234,567
# Packets dropped: 0 (0.0%)
# CPU usage: 45%
# Memory usage: 512MB / 2GB
```

**チューニング**:
```yaml
resources:
  requests:
    memory: "1Gi"     # 増加
    cpu: "500m"       # 増加
  limits:
    memory: "4Gi"     # 増加
    cpu: "2000m"      # 増加
```

---

## ベストプラクティス

### 1. 最小権限の原則

**❌ 悪い例**:
```yaml
securityContext:
  privileged: true  # すべての権限を付与
```

**✅ 良い例**:
```yaml
securityContext:
  capabilities:
    add:
    - SYS_ADMIN      # eBPFに必要
    - NET_ADMIN      # ネットワーク操作に必要
    - NET_RAW        # パケットキャプチャに必要
    drop:
    - ALL            # その他はすべてドロップ
```

### 2. Namespace分離

**推奨構成**:
```
monitoring namespace: StratoShark DaemonSet
production namespace: アプリケーション Pod

→ 分離することでセキュリティ向上
```

### 3. ラベルとアノテーションの活用

```yaml
metadata:
  labels:
    app: stratoshark
    component: monitoring
    managed-by: ops-team
  annotations:
    description: "Network packet capture and analysis"
    contact: "sre-team@example.com"
```

### 4. ログローテーション

```bash
# ストレージ満杯を防ぐ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  sh -c "find /var/log/captures -name '*.pcap*' -mtime +7 -delete"
```

### 5. セキュリティ考慮事項

**機密情報の保護**:
```bash
# キャプチャファイルに機密情報が含まれる可能性
# → アクセス制限を設定

# ConfigMapでフィルタを管理
kubectl create configmap stratoshark-filter \
  --from-literal=filter="tcp port 80 or tcp port 443" \
  -n monitoring

# Secretとして保存しない（平文キャプチャのため）
```

---

## トラブルシューティング

### 問題1: eBPFメタデータが表示されない

**症状**: Pod名やNamespace情報が表示されない

**解決策**:
```bash
# 1. eBPFが有効か確認
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark --version | grep eBPF

# 2. カーネルバージョン確認
kubectl exec -n monitoring stratoshark-xxxxx -- uname -r
# → 5.8以上が必要

# 3. コンテナランタイムのソケットがマウントされているか確認
kubectl describe pod -n monitoring stratoshark-xxxxx | grep -A5 volumeMounts
# → /run/containerd がマウントされているべき
```

### 問題2: DaemonSetがスケジュールされない

**症状**: 一部のノードでStratoShark Podが起動しない

**解決策**:
```bash
# Taintを確認
kubectl describe node <node-name> | grep Taints

# Tolerationを追加
tolerations:
- key: node-role.kubernetes.io/master
  effect: NoSchedule
- key: node.kubernetes.io/disk-pressure
  effect: NoSchedule
```

### 問題3: パケットドロップが多発

**症状**: `Packets dropped: 15%`

**解決策**:
```bash
# 1. バッファサイズを増やす
--buffer-size 128M

# 2. フィルタを適用
--ebpf-filter "k8s.namespace == production"

# 3. スナップレングスを減らす
--snaplen 96  # ヘッダのみ

# 4. CPUリミットを増やす
resources:
  limits:
    cpu: "2000m"
```

---

## まとめ

本章では、StratoSharkのKubernetes統合機能を学びました：

✅ **DaemonSetデプロイ**: クラスタ全体での監視
✅ **eBPFメタデータ**: Pod/Container/Service情報の自動取得
✅ **Pod単位キャプチャ**: 特定Podのトラフィック分離
✅ **Service解析**: ClusterIP/NodePort/LoadBalancerの追跡
✅ **Ingress/Egress**: 外部通信の監視
✅ **Service Mesh**: Istio/Linkerd統合
✅ **NetworkPolicy検証**: ポリシーの動作確認
✅ **CNI統合**: Calico/Cilium/Flannel対応
✅ **DNS追跡**: CoreDNS解決の解析
✅ **マルチクラスタ**: Cluster間通信の監視
✅ **実践例**: 4つの実際のトラブルシューティングシナリオ

次章では、これらの機能を活用したSRE実務での実践例を詳しく解説します。障害対応、パフォーマンス改善、セキュリティ監査など、実際の運用シーンでの活用方法を学びます。
