---
title: "SRE実務例 ― 現場で使える実践テクニック"
---

# SRE実務例

## 本章の目的

実際のSRE業務でStratoSharkをどう活用するかを学びます。パフォーマンス問題の調査、インシデント対応、容量計画、セキュリティ監査など、現場で直面する具体的なシナリオと解決策を解説します。

## SREにおけるネットワーク解析の重要性

### SREの4つの柱とStratoShark

```
┌─────────────────────────────────────────────────────┐
│            SREの4つの柱                               │
├─────────────────────────────────────────────────────┤
│ 1. モニタリング                                        │
│    → StratoShark: リアルタイムネットワーク監視         │
│                                                        │
│ 2. インシデント対応                                    │
│    → StratoShark: 障害時のトラフィック解析            │
│                                                        │
│ 3. ポストモーテム                                      │
│    → StratoShark: 過去のキャプチャデータ分析          │
│                                                        │
│ 4. 容量計画                                           │
│    → StratoShark: トラフィックパターン分析            │
└─────────────────────────────────────────────────────┘
```

### StratoSharkが解決するSREの課題

| 課題 | 従来の方法 | StratoSharkでの解決 |
|------|-----------|-------------------|
| **マイクロサービス間の遅延** | ログから推測 | パケットレベルで測定 |
| **間欠的な障害** | 再現困難 | 連続キャプチャで証拠保全 |
| **Kubernetes Pod間通信** | 推測困難 | eBPFで完全可視化 |
| **TLS/mTLS問題** | デバッグ困難 | 証明書とハンドシェイク検証 |
| **ネットワークポリシー** | 動作不明確 | 実際のパケット挙動を確認 |

---

## ケーススタディ1: E-Commerce サイトのパフォーマンス劣化

### 背景

**システム構成**:
```
Internet
  ↓
Ingress (NGINX)
  ↓
Frontend Service (React SPA)
  ↓
Backend API Service (Node.js)
  ↓
Database (PostgreSQL)
  ↓
Cache (Redis)
```

**問題**:
- 顧客からの報告: 「商品ページの読み込みが遅い」
- Grafanaのメトリクス: API Response Timeが平均2秒（通常は200ms）
- エラーログ: なし
- CPUとメモリ: 正常範囲内

### 調査フェーズ1: 問題の特定

**ステップ1: Ingressトラフィックをキャプチャ**

```bash
# Ingress Controller Podを特定
kubectl get pods -n ingress-nginx

# キャプチャ開始（5分間）
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.pod contains nginx-ingress" \
    --duration 5m \
    --output /tmp/ingress-traffic.pcap
```

**ステップ2: GUIで解析**

```
# HTTPリクエストを表示
フィルタ: http

# レスポンスタイムでソート
Statistics → Service Response Time → HTTP
```

**発見**:
```
URI Path              Count  Avg (ms)  Max (ms)  Min (ms)
/api/products         234    1,987     5,432     156
/api/cart             123    2,134     6,123     189
/api/user             89     234       456       123      ← 正常
/                     456    123       234       45       ← 正常
```

→ `/api/products` と `/api/cart` が異常に遅い

**ステップ3: Backend API Podのトラフィックをキャプチャ**

```bash
# Backend API PodのIPを取得
BACKEND_IP=$(kubectl get pod -n production backend-api-abc123 -o jsonpath='{.status.podIP}')

# キャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.pod == backend-api-abc123" \
    --duration 5m \
    --output /tmp/backend-api-traffic.pcap
```

**ステップ4: TCPストリームを追跡**

```
# GUIで開く
stratoshark backend-api-traffic.pcap

# /api/products のリクエストを選択
# Follow → TCP Stream
```

**観察**:
```
Client → Backend: GET /api/products HTTP/1.1
  Time: 0.000

Backend → Database: SELECT * FROM products (PostgreSQL)
  Time: 0.005  ← クエリ送信

Database → Backend: (応答なし)
  Time: 0.005 ~ 1.987 (1.982秒待機！)

Database → Backend: Query Result
  Time: 1.987

Backend → Client: HTTP/1.1 200 OK
  Time: 1.995
```

→ **データベースクエリが1.9秒かかっている**

### 調査フェーズ2: データベース通信の深堀り

**ステップ5: Database Podのトラフィックをキャプチャ**

```bash
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.pod == postgres-0" \
    --duration 5m \
    --output /tmp/postgres-traffic.pcap
```

**ステップ6: TCPウィンドウ分析**

```
Statistics → TCP Stream Graphs → Window Scaling Graph
```

**発見**:
```
Window Size (bytes)
  │
  │ 65535 ─────────
  │ 32768 ─────────    ← 受信ウィンドウが小さい
  │ 16384 ─────────
  │  8192 ─────────
  │     0 ────╲╲╲╲    ← ゼロウィンドウ頻発！
  └──────────────────→ Time
```

→ PostgreSQLの受信バッファが満杯

**ステップ7: eBPFメタデータを確認**

```
▼ eBPF Metadata (postgres-0)
  ├─ Process Name: postgres
  ├─ CPU Usage: 15%      ← CPU は正常
  ├─ Memory Usage: 85%   ← メモリが逼迫！
  └─ TCP Buffer: Full    ← TCP受信バッファ満杯
```

### 根本原因

PostgreSQL Podのメモリリミットが低すぎて、TCP受信バッファが不足している。

### 解決策

```yaml
# PostgreSQL StatefulSetのリソース設定を変更
resources:
  requests:
    memory: "2Gi"    # 元: 512Mi
  limits:
    memory: "4Gi"    # 元: 1Gi
```

**適用**:
```bash
kubectl apply -f postgres-statefulset.yaml
kubectl rollout status statefulset/postgres -n production
```

### 検証

```bash
# 再度キャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.pod == postgres-0" \
    --duration 5m \
    --output /tmp/postgres-after.pcap

# GUIで比較
stratoshark postgres-after.pcap
```

**結果**:
```
Statistics → Service Response Time → HTTP

URI Path              Count  Avg (ms)  Max (ms)  Min (ms)
/api/products         234    187       345       123      ← 改善！
/api/cart             123    195       378       134      ← 改善！
```

**改善率**: 2,000ms → 190ms（**10倍以上高速化**）

---

## ケーススタディ2: 間欠的なAPI障害

### 背景

**問題**:
- 1時間に1〜2回、APIが503エラーを返す
- エラーログ: `upstream timeout`
- 再現性: 低い（ランダムに発生）
- 影響範囲: 全APIエンドポイント

### 調査戦略

間欠的な問題は「常時キャプチャ + アラート連動」で証拠を保全します。

**ステップ1: 継続的なキャプチャを設定**

```bash
# DaemonSetのStratoSharkで24時間キャプチャ（ローテーション）
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.namespace == production" \
    --output /var/log/captures/traffic.pcap \
    --rotate-time 1h \
    --rotate-files 24 \
    --compress gzip
```

**生成されるファイル**:
```
/var/log/captures/
  ├─ traffic_2025-01-10_10:00.pcap.gz
  ├─ traffic_2025-01-10_11:00.pcap.gz
  ├─ traffic_2025-01-10_12:00.pcap.gz
  └─ ...
```

**ステップ2: Prometheusアラートと連動**

```yaml
# prometheus-alert.yaml
groups:
- name: api-errors
  rules:
  - alert: HighAPIErrorRate
    expr: |
      rate(http_requests_total{status=~"5.."}[5m]) > 0.01
    for: 1m
    annotations:
      summary: "API error rate is high"
      description: "{{ $labels.pod }} is returning 5xx errors"
      stratoshark_capture: "traffic_{{ $labels.timestamp | date '2006-01-02_15:04' }}.pcap.gz"
```

**ステップ3: アラート発生時刻を特定**

```bash
# Prometheusからアラート履歴を取得
curl -s 'http://prometheus:9090/api/v1/query?query=ALERTS{alertname="HighAPIErrorRate"}' | jq

# 結果
# timestamp: 2025-01-10T14:23:45Z
```

**ステップ4: 該当時刻のpcapを解析**

```bash
# ファイルをローカルにコピー
kubectl cp monitoring/stratoshark-xxxxx:/var/log/captures/traffic_2025-01-10_14:00.pcap.gz \
  ./incident-2025-01-10.pcap.gz

# 解凍
gunzip incident-2025-01-10.pcap.gz

# GUIで開く
stratoshark incident-2025-01-10.pcap
```

**ステップ5: 14:23:45前後のトラフィックを抽出**

```
# 時刻でフィルタ
frame.time >= "2025-01-10 14:20:00" && frame.time <= "2025-01-10 14:25:00"

# 503エラーを抽出
http.response.code == 503
```

**ステップ6: Expert Informationを確認**

```
Analyze → Expert Information → Error
```

**発見**:
```
[Error] TCP Connection Reset
  Packet: 12345
  Time: 14:23:44.567

[Error] TCP Retransmission
  Packet: 12346-12360
  Time: 14:23:44.567 ~ 14:23:45.123
```

**ステップ7: TCPストリームを追跡**

```
右クリック → Follow TCP Stream
```

**観察**:
```
Client → API: POST /api/checkout HTTP/1.1
  Time: 14:23:44.000

API → Database: BEGIN TRANSACTION
  Time: 14:23:44.100

Database → API: (応答なし)
  Time: 14:23:44.100 ~ 14:23:59.100 (15秒待機)

API → Client: [RST] (タイムアウト)
  Time: 14:23:59.101

Client → API: HTTP 503 Service Unavailable
  Time: 14:23:59.102
```

**ステップ8: eBPFでデータベース側を確認**

```
フィルタ: ebpf.k8s.pod == "postgres-0"

# eBPF Metadata
▼ eBPF Metadata
  ├─ Deadlock Detected: true   ← デッドロック！
  ├─ Blocked Transactions: 5
  └─ Wait Time: 15.2s
```

### 根本原因

PostgreSQLでデッドロックが発生し、トランザクションがタイムアウト。

### 解決策

**短期対応**:
```sql
-- デッドロック監視クエリを追加
SELECT blocked_locks.pid AS blocked_pid,
       blocking_locks.pid AS blocking_pid,
       blocked_activity.query AS blocked_statement
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity
  ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks
  ON blocking_locks.locktype = blocked_locks.locktype
WHERE NOT blocked_locks.granted;
```

**長期対応**:
```python
# アプリケーション側でリトライロジック追加
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def checkout_transaction():
    try:
        with db.begin():
            # トランザクション処理
            pass
    except DatabaseError as e:
        if "deadlock detected" in str(e):
            logger.warning("Deadlock detected, retrying...")
            raise
```

---

## ケーススタディ3: Istio Service Mesh の証明書問題

### 背景

**問題**:
- マイクロサービス間通信が突然失敗（HTTP 503）
- Envoy Proxyログ: `TLS error: certificate verify failed`
- 影響: 本番環境の全Service Mesh通信

### 調査手順

**ステップ1: Envoy Sidecarのトラフィックをキャプチャ**

```bash
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.namespace == production" \
    --filter "tcp port 15001 or tcp port 15006" \
    --duration 5m \
    --output /tmp/istio-mtls-error.pcap
```

**ステップ2: TLSハンドシェイクを解析**

```
フィルタ: tls.handshake

# TLSアラートを確認
tls.alert_message
```

**発見**:
```
▼ TLSv1.3 Alert: Certificate Expired
  Level: Fatal
  Description: certificate expired (45)
  Time: 2025-01-10 15:30:12.345
```

**ステップ3: 証明書情報を詳細確認**

```
# Client Hello パケットを選択
▼ Transport Layer Security
  ▼ Handshake Protocol: Certificate
    ▼ Certificate: spiffe://cluster.local/ns/production/sa/frontend
      - Subject: O=cluster.local
      - Issuer: O=cluster.local, CN=istio-ca
      - Valid From: 2025-01-09 15:30:00
      - Valid Until: 2025-01-10 15:30:00  ← 12秒前に期限切れ！
```

**ステップ4: 全Podの証明書を確認**

```bash
# スクリプトで全Pod確認
for pod in $(kubectl get pods -n production -o name); do
  echo "=== $pod ==="
  kubectl exec -n production $pod -c istio-proxy -- \
    openssl s_client -connect localhost:15006 -showcerts </dev/null 2>/dev/null | \
    openssl x509 -noout -dates
done
```

**結果**:
```
=== pod/frontend-abc123 ===
notBefore=Jan  9 15:30:00 2025 GMT
notAfter=Jan 10 15:30:00 2025 GMT  ← 期限切れ

=== pod/backend-xyz789 ===
notBefore=Jan  9 15:30:00 2025 GMT
notAfter=Jan 10 15:30:00 2025 GMT  ← 期限切れ

=== pod/database-def456 ===
notBefore=Jan 10 15:35:00 2025 GMT
notAfter=Jan 11 15:35:00 2025 GMT  ← 正常（新しい証明書）
```

### 根本原因

Istio Citadel（証明書発行機関）が一時的にダウンし、証明書の自動更新に失敗。

### 解決策

```bash
# Istio Citadelを再起動
kubectl rollout restart deployment/istiod -n istio-system

# 証明書の再発行を待つ（通常1-2分）
sleep 120

# 全Podの証明書を確認
kubectl exec -n production frontend-abc123 -c istio-proxy -- \
  openssl s_client -connect localhost:15006 -showcerts </dev/null 2>/dev/null | \
  openssl x509 -noout -dates

# 結果:
# notAfter=Jan 11 15:40:00 2025 GMT  ← 更新成功！
```

### 検証

```bash
# 再度キャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.namespace == production" \
    --filter "tcp port 15001" \
    --duration 2m \
    --output /tmp/istio-mtls-fixed.pcap

# GUIで確認
stratoshark istio-mtls-fixed.pcap
```

**結果**:
```
# TLSハンドシェイクが成功
▼ TLSv1.3 Handshake: Server Hello
  Cipher Suite: TLS_AES_128_GCM_SHA256
  Status: Success

# アラートなし
tls.alert_message → (0 packets)
```

---

## ケーススタディ4: DDoS攻撃の検出と対応

### 背景

**問題**:
- Ingressへのトラフィックが急増（通常の10倍）
- 正規ユーザーがアクセスできない
- WAFアラート: 大量の不審なリクエスト

### 調査フェーズ1: 攻撃パターンの特定

**ステップ1: Ingressトラフィックをキャプチャ**

```bash
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.pod contains nginx-ingress" \
    --duration 5m \
    --output /tmp/ddos-attack.pcap
```

**ステップ2: トップトーカーを特定**

```
Statistics → Endpoints → IPv4
```

**結果**:
```
Address          Packets   Bytes       Tx Packets  Rx Packets
203.0.113.45     234,567   345 MB      117,000     117,567     ← 異常！
203.0.113.46     198,234   289 MB      99,000      99,234      ← 異常！
203.0.113.47     187,456   276 MB      93,000      94,456      ← 異常！
192.0.2.123      1,234     1.2 MB      617         617         ← 正常
192.0.2.124      987       987 KB      493         494         ← 正常
```

→ **203.0.113.0/24** からの大量トラフィック

**ステップ3: リクエストパターンを解析**

```
フィルタ: ip.src == 203.0.113.45 && http

Statistics → HTTP → Requests
```

**結果**:
```
URI Path              Count    User-Agent
/api/search           123,456  Mozilla/5.0 (Bot)
/api/search           87,234   curl/7.68.0
/api/search           23,877   Python-requests/2.28.0
```

→ `/api/search` への大量リクエスト（検索API攻撃）

**ステップ4: リクエストレートを測定**

```
Statistics → I/O Graph

# 設定:
# Y軸: Packets/sec
# フィルタ1: ip.src == 203.0.113.45
# フィルタ2: ip.src == 192.0.2.0/24 (正規ユーザー)
```

**グラフ**:
```
Packets/sec
  │
  │ ████████████████  ← 攻撃トラフィック（5,000 pkt/s）
  │ █
  │ █  ██            ← 正規トラフィック（100 pkt/s）
  └──────────────────→ Time
```

### 対応フェーズ1: 緊急ブロック

```bash
# NetworkPolicyで攻撃元IPをブロック
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-ddos-sources
  namespace: ingress-nginx
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: ingress-nginx
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 203.0.113.0/24  # ブロック
EOF
```

**検証**:
```bash
# 再度キャプチャ
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.pod contains nginx-ingress" \
    --duration 2m \
    --output /tmp/after-block.pcap

# GUIで確認
stratoshark after-block.pcap
```

**結果**:
```
Statistics → Endpoints → IPv4

Address          Packets   Bytes
203.0.113.45     0         0 B        ← ブロック成功！
192.0.2.123      1,234     1.2 MB     ← 正規トラフィック復旧
192.0.2.124      987       987 KB     ← 正規トラフィック復旧
```

### 対応フェーズ2: レート制限の実装

```yaml
# nginx-ingress ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-configuration
  namespace: ingress-nginx
data:
  # レート制限（1秒あたり10リクエスト）
  limit-req-zone: "$binary_remote_addr zone=api_search:10m rate=10r/s"
  limit-req-status-code: "429"
```

**適用**:
```bash
kubectl apply -f nginx-configmap.yaml
kubectl rollout restart deployment/nginx-ingress-controller -n ingress-nginx
```

### ポストモーテム分析

**ステップ1: 攻撃の時系列を可視化**

```
Statistics → I/O Graph

# 設定:
# X軸: 1分間隔
# Y軸: Bytes/sec
# 期間: 過去24時間のpcapをマージ
```

**グラフ**:
```
Traffic (Mbps)
  │
  │                   ████████
  │                   ██    ██
  │ ─────────────────███────███─────────
  │                         ↑
  └─────────────────────────┼───────────→ Time
                      攻撃開始
                   (14:23 UTC)
```

**ステップ2: 被害範囲を特定**

```
# 攻撃時間中の正規ユーザーの影響を測定
フィルタ: http && !(ip.src == 203.0.113.0/24)

Statistics → Service Response Time → HTTP
```

**結果**:
```
Time Range          Avg (ms)  Max (ms)
14:00-14:20 (攻撃前)   187       456      ← 正常
14:23-14:45 (攻撃中)   8,456     45,123   ← 45倍遅延！
14:46-15:00 (復旧後)   195       489      ← 正常復帰
```

---

## Prometheus/Grafana統合

### StratoSharkメトリクスのエクスポート

StratoSharkから取得したネットワークメトリクスをPrometheusに送信します。

**アーキテクチャ**:
```
StratoShark
  ↓ (eBPF)
Network Metrics
  ↓ (Export)
Prometheus Exporter (:9090)
  ↓ (Scrape)
Prometheus
  ↓ (Query)
Grafana Dashboard
```

### カスタムExporterの実装

```python
# stratoshark_exporter.py
from prometheus_client import start_http_server, Gauge, Counter
import subprocess
import json
import time

# メトリクス定義
packets_total = Counter('stratoshark_packets_total', 'Total packets captured', ['pod', 'namespace'])
bytes_total = Counter('stratoshark_bytes_total', 'Total bytes captured', ['pod', 'namespace'])
tcp_retransmissions = Counter('stratoshark_tcp_retransmissions_total', 'TCP retransmissions', ['pod'])
http_response_time = Gauge('stratoshark_http_response_time_seconds', 'HTTP response time', ['pod', 'method'])

def collect_metrics():
    # StratoSharkから統計を取得
    result = subprocess.run([
        'stratoshark', '-r', '/var/log/captures/latest.pcap',
        '-q', '-z', 'io,stat,1'
    ], capture_output=True, text=True)

    # パース処理
    for line in result.stdout.split('\n'):
        if 'ebpf.k8s.pod' in line:
            pod, packets, bytes_count = parse_line(line)
            packets_total.labels(pod=pod, namespace='production').inc(packets)
            bytes_total.labels(pod=pod, namespace='production').inc(bytes_count)

    # TCP Retransmissionを取得
    result = subprocess.run([
        'stratoshark', '-r', '/var/log/captures/latest.pcap',
        '-Y', 'tcp.analysis.retransmission',
        '-T', 'json'
    ], capture_output=True, text=True)

    for packet in json.loads(result.stdout):
        pod = packet['_source']['layers']['ebpf']['k8s.pod']
        tcp_retransmissions.labels(pod=pod).inc()

if __name__ == '__main__':
    # Prometheusエクスポーターを起動
    start_http_server(9090)
    print("StratoShark Exporter listening on :9090")

    while True:
        collect_metrics()
        time.sleep(60)  # 1分ごとに収集
```

### Prometheus設定

```yaml
# prometheus.yaml
scrape_configs:
- job_name: 'stratoshark'
  static_configs:
  - targets: ['stratoshark-exporter:9090']
  scrape_interval: 60s
```

### Grafanaダッシュボード

```json
{
  "dashboard": {
    "title": "StratoShark Network Metrics",
    "panels": [
      {
        "title": "Packets per Second by Pod",
        "targets": [
          {
            "expr": "rate(stratoshark_packets_total[5m])"
          }
        ],
        "type": "graph"
      },
      {
        "title": "TCP Retransmissions",
        "targets": [
          {
            "expr": "rate(stratoshark_tcp_retransmissions_total[5m])"
          }
        ],
        "type": "graph"
      },
      {
        "title": "HTTP Response Time P95",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(stratoshark_http_response_time_bucket[5m]))"
          }
        ],
        "type": "graph"
      }
    ]
  }
}
```

**ダッシュボード例**:
```
┌────────────────────────────────────────────────────┐
│ StratoShark Network Metrics                        │
├────────────────────────────────────────────────────┤
│                                                     │
│ Packets per Second by Pod                          │
│ ┌─────────────────────────────────────────────┐   │
│ │   frontend-pod  ████████                    │   │
│ │   backend-pod   ██████                      │   │
│ │   db-pod        ███                         │   │
│ └─────────────────────────────────────────────┘   │
│                                                     │
│ TCP Retransmissions                                │
│ ┌─────────────────────────────────────────────┐   │
│ │   0.5%  ────────────                        │   │
│ │   0.3%      ────                            │   │
│ └─────────────────────────────────────────────┘   │
│                                                     │
│ HTTP Response Time P95                             │
│ ┌─────────────────────────────────────────────┐   │
│ │   250ms ────────────                        │   │
│ │   150ms     ────                            │   │
│ └─────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────┘
```

---

## アラート設定

### ネットワークメトリクスに基づくアラート

```yaml
# prometheus-alerts.yaml
groups:
- name: network_alerts
  rules:
  # TCP再送信率が高い
  - alert: HighTCPRetransmissionRate
    expr: |
      rate(stratoshark_tcp_retransmissions_total[5m]) > 0.01
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High TCP retransmission rate on {{ $labels.pod }}"
      description: "{{ $labels.pod }} has {{ $value | humanizePercentage }} TCP retransmissions"

  # HTTPレスポンスタイムが遅い
  - alert: SlowHTTPResponseTime
    expr: |
      histogram_quantile(0.95,
        rate(stratoshark_http_response_time_bucket[5m])
      ) > 1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Slow HTTP response time on {{ $labels.pod }}"
      description: "P95 response time is {{ $value }}s"

  # パケットドロップが発生
  - alert: PacketDropDetected
    expr: |
      rate(stratoshark_packets_dropped_total[5m]) > 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Packet drops detected on {{ $labels.node }}"
      description: "{{ $value }} packets/sec are being dropped"

  # ゼロウィンドウが頻発
  - alert: FrequentZeroWindow
    expr: |
      rate(stratoshark_tcp_zero_window_total[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Frequent TCP zero window on {{ $labels.pod }}"
      description: "Pod {{ $labels.pod }} is experiencing TCP flow control issues"
```

### PagerDuty/Slack通知

```yaml
# alertmanager.yaml
receivers:
- name: 'slack-network-alerts'
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/XXX/YYY/ZZZ'
    channel: '#network-alerts'
    title: 'Network Alert: {{ .GroupLabels.alertname }}'
    text: |
      *Summary:* {{ .CommonAnnotations.summary }}
      *Description:* {{ .CommonAnnotations.description }}
      *StratoShark Capture:* `/var/log/captures/traffic_{{ .StartsAt | date "2006-01-02_15:04" }}.pcap.gz`

route:
  group_by: ['alertname', 'pod']
  receiver: 'slack-network-alerts'
  routes:
  - match:
      severity: critical
    receiver: 'pagerduty'
```

**Slack通知例**:
```
Network Alert: HighTCPRetransmissionRate
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: High TCP retransmission rate on backend-api-abc123
Description: backend-api-abc123 has 2.3% TCP retransmissions
StratoShark Capture: /var/log/captures/traffic_2025-01-10_14:00.pcap.gz

[View in Grafana] [View in StratoShark] [Acknowledge]
```

---

## 容量計画

### トラフィックパターン分析

**目的**: 将来のリソース要件を予測

**ステップ1: 長期間のトラフィックデータを収集**

```bash
# 1週間分のキャプチャ（1時間ごとにローテーション）
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --ebpf-filter "k8s.namespace == production" \
    --output /var/log/captures/traffic.pcap \
    --rotate-time 1h \
    --rotate-files 168 \  # 24時間 × 7日
    --compress gzip
```

**ステップ2: 時間帯別のトラフィック統計を生成**

```bash
# スクリプトで全pcapを解析
for pcap in /var/log/captures/traffic_*.pcap.gz; do
  hour=$(basename $pcap | cut -d'_' -f2)
  echo "=== Hour: $hour ==="

  stratoshark -r $pcap -q -z io,stat,3600 | \
    grep -A5 "Statistics" | \
    awk '{print $hour, $2, $3, $4}'
done > traffic_stats.csv
```

**ステップ3: GrafanaでGrafana Explore  可視化**

```sql
SELECT
  time_bucket('1 hour', timestamp) AS hour,
  avg(packets_per_sec) AS avg_pps,
  max(packets_per_sec) AS max_pps,
  avg(bytes_per_sec) AS avg_bps
FROM stratoshark_metrics
WHERE timestamp > now() - interval '7 days'
GROUP BY hour
ORDER BY hour
```

**グラフ例**:
```
Packets/sec
  │
  │     ╱╲      ╱╲      ╱╲      ╱╲
  │    ╱  ╲    ╱  ╲    ╱  ╲    ╱  ╲   ← ピーク時間帯
  │   ╱    ╲  ╱    ╲  ╱    ╲  ╱    ╲
  │  ╱      ╲╱      ╲╱      ╲╱      ╲
  └────────────────────────────────────→ Time (7 days)
    0時   6時  12時  18時  24時
```

**分析結果**:
```
時間帯         平均 (pps)  ピーク (pps)  増加率
00:00-06:00    1,234       2,345         -
06:00-12:00    8,456       15,678        +585%
12:00-18:00    12,345      23,456        +900%
18:00-24:00    6,789       12,345        +450%
```

**予測**:
- ピーク時間帯: 12:00-18:00
- 月間成長率: 15%
- 3ヶ月後の予測ピーク: 23,456 × 1.15³ = **35,678 pps**

**リソース計画**:
```
現在のIngress Controller: 2レプリカ（各10,000 pps処理可能）
→ 3ヶ月後に必要: 4レプリカ（35,678 / 10,000 = 3.57）
```

---

## セキュリティ監査

### 不審なトラフィックの検出

**シナリオ**: 内部ネットワークからの不審な外部通信を検出

**ステップ1: Egressトラフィックをキャプチャ**

```bash
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --filter "not dst net 10.0.0.0/8 and not dst net 172.16.0.0/12" \
    --duration 24h \
    --output /tmp/egress-audit.pcap
```

**ステップ2: GUIで解析**

```
Statistics → Conversations → TCP

# 外部宛先でソート
```

**発見**:
```
Source          Dest                    Packets  Bytes
10.244.1.5      198.51.100.123:443      12,345   15 MB    ← 正常（CDN）
10.244.2.10     203.0.113.45:22         234      345 KB   ← 不審！SSHポート
10.244.2.10     203.0.113.46:4444       567      1.2 MB   ← 不審！非標準ポート
```

**ステップ3: 不審なPodを特定**

```
フィルタ: ip.src == 10.244.2.10

# eBPF Metadata
▼ eBPF Metadata
  ├─ Pod Name: suspicious-pod-xyz789
  ├─ Namespace: production
  ├─ Container Name: app
  └─ Process Name: /tmp/.hidden/backdoor  ← 不審！
```

**ステップ4: パケット内容を確認**

```
Follow → TCP Stream
```

**観察**:
```
# SSH接続試行
SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5

# 非標準ポート（4444）
POST /api/exfiltrate HTTP/1.1
Host: 203.0.113.46:4444
Content-Type: application/octet-stream
Content-Length: 1234567

[Binary Data - Possibly Sensitive Files]
```

→ **データ流出の可能性**

**ステップ5: 緊急対応**

```bash
# 1. Podを隔離
kubectl label pod suspicious-pod-xyz789 -n production quarantine=true

# 2. NetworkPolicyで外部通信をブロック
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-pod
  namespace: production
spec:
  podSelector:
    matchLabels:
      quarantine: "true"
  policyTypes:
  - Egress
  egress: []  # すべてのEgressをブロック
EOF

# 3. インシデントレスポンスチームに通知
```

---

## ベストプラクティス

### 1. 常時キャプチャの設定

**❌ 悪い例**:
```bash
# 問題発生後にキャプチャ開始（証拠が残らない）
```

**✅ 良い例**:
```bash
# 24時間365日キャプチャ（ローテーション+圧縮）
kubectl exec -n monitoring stratoshark-xxxxx -- \
  stratoshark capture \
    --output /var/log/captures/traffic.pcap \
    --rotate-time 1h \
    --rotate-files 168 \  # 1週間分保持
    --compress gzip \
    --snaplen 96  # ヘッダのみ（ストレージ節約）
```

### 2. アラートとキャプチャの連動

**推奨構成**:
```
Prometheus Alert
  ↓ (Webhook)
Alertmanager
  ↓ (Annotation)
StratoShark Capture File Reference
  ↓
Grafana Dashboard (リンク)
  ↓ (ダウンロード)
StratoShark GUI分析
```

### 3. 定期的なポストモーテム

```
週次レビュー:
- 先週のインシデント一覧
- StratoSharkキャプチャの活用状況
- 検出できなかった問題
- ツールの改善点
```

### 4. セキュリティとプライバシー

**重要事項**:
- キャプチャファイルには機密情報が含まれる可能性
- アクセス制限を設定
- 暗号化ストレージを使用
- 保持期間を定義（GDPR等の規制遵守）

```bash
# キャプチャファイルの暗号化
kubectl exec -n monitoring stratoshark-xxxxx -- \
  sh -c "stratoshark capture --output - | gpg --encrypt --recipient ops@example.com > /tmp/capture.pcap.gpg"
```

### 5. チーム教育

**推奨トレーニング**:
- StratoShark基本操作（全SREメンバー）
- 高度なフィルタリング（シニアSRE）
- eBPF機能の活用（専門チーム）
- セキュリティ調査（セキュリティチーム）

---

## まとめ

本章では、StratoSharkを活用したSRE実務での実践例を学びました：

✅ **ケーススタディ1**: E-Commerceパフォーマンス劣化 → PostgreSQL TCPバッファ不足
✅ **ケーススタディ2**: 間欠的API障害 → データベースデッドロック検出
✅ **ケーススタディ3**: Istio mTLS通信エラー → 証明書期限切れ検出
✅ **ケーススタディ4**: DDoS攻撃 → 攻撃元特定とレート制限実装
✅ **Prometheus/Grafana統合**: ネットワークメトリクスの可視化
✅ **アラート設定**: TCP再送信、HTTPレスポンスタイム、パケットドロップ
✅ **容量計画**: トラフィックパターン分析と将来予測
✅ **セキュリティ監査**: 不審なEgressトラフィック検出とデータ流出対策
✅ **ベストプラクティス**: 常時キャプチャ、アラート連動、ポストモーテム

次章では、StratoSharkをeBPFエコシステムの他のツール（Falco、Cilium、Tetragon等）と統合する方法を学びます。統合されたObservabilityスタックで、より包括的なシステム監視を実現します。
