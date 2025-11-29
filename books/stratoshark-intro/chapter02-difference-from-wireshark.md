---
title: "Wiresharkとの違い ― なぜStratoSharkが生まれたのか？"
---

# Wiresharkとの違い

## 本章の目的

前章でStratoSharkの概要を学びました。本章では、**なぜWiresharkという強力なツールがあるのにStratoSharkが必要なのか**を深く理解していきます。

## Wiresharkの歴史と課題

### Wiresharkの誕生（1998年〜）

Wireshark（当初はEthereal）は、**Gerald Combs氏によって1998年に開発が開始**されました。以来25年以上にわたり、ネットワーク解析のデファクトスタンダードとして進化を続けています。

### Wiresharkの強み

| 強み | 詳細 |
|------|------|
| **プロトコルサポート** | 3000以上のプロトコルに対応 |
| **詳細な解析** | パケットの各フィールドを完全に解析 |
| **クロスプラットフォーム** | Windows/macOS/Linux対応 |
| **成熟したツール** | 20年以上の実績と豊富なドキュメント |
| **強力なフィルタ** | 柔軟な表示フィルタとキャプチャフィルタ |

### しかし、クラウド時代の課題も

Wiresharkは強力ですが、**クラウドネイティブ環境では以下の課題**があります。

## クラウドネイティブ環境での具体的な課題と解決策

StratoSharkが解決する課題を、実践的な例とともに詳しく見ていきましょう。

## 課題1: 「Podに入らないとキャプチャできない」

### 従来の方法の問題点

Kubernetes環境で最も頻繁に遭遇する問題です。

**典型的なトラブルシューティングフロー**:
```bash
# 1. Podにログイン
kubectl exec -it my-app-xyz -- /bin/sh

# 2. tcpdumpがない...
$ tcpdump
sh: tcpdump: not found

# 3. 他の方法を試す
$ apt-get update && apt-get install tcpdump
# => エラー: イメージがdistrolessで、パッケージマネージャーがない
```

**多くの本番環境の制約**:
- ✗ Distrolessイメージでツールが入っていない
- ✗ セキュリティポリシーでPod変更が制限されている
- ✗ デバッグツールのインストールが許可されていない
- ✗ 本番環境でイメージを変更するのはリスクが高い

### StratoSharkの解決策

**ホストから直接キャプチャ（Podに入る必要なし）**:
```bash
# Podを指定してキャプチャ
stratoshark capture \
  --namespace production \
  --pod my-app-xyz \
  --output /tmp/capture.pcap

# 結果をリアルタイムで確認
stratoshark capture \
  --pod my-app-xyz \
  --filter "http" \
  --live
```

**メリット**:
- ✅ Podのイメージを変更する必要なし
- ✅ distrolessイメージでも動作
- ✅ 本番環境を一切変更せずにキャプチャ
- ✅ セキュリティポリシーに準拠

### 権限管理：root不要の仕組み

**問題点**:
```bash
# 従来のツールではroot権限が必須
sudo tcpdump -i eth0
sudo wireshark
```

- 本番環境でroot権限を付与するのはセキュリティリスク
- 開発者が気軽にデバッグできない
- 権限昇格の申請プロセスが煩雑

**StratoSharkの解決策**:

eBPFのcapability機能を活用：
```bash
# CAP_BPFとCAP_NET_ADMINを付与（初回のみ）
sudo setcap 'cap_bpf,cap_net_admin+ep' /usr/bin/stratoshark

# 以降は一般ユーザーで実行可能
stratoshark capture --interface eth0
```

:::message
**Linux Capability とは？**
Linux のcapability機能を使うと、root権限を全て渡さずに、必要な権限だけを付与できます。StratoSharkに必要なのは：
- `CAP_BPF`: eBPFプログラムのロード
- `CAP_NET_ADMIN`: ネットワーク管理操作

これにより、**最小権限の原則**を守りながらツールを実行できます。
:::

### 課題2: Kubernetes環境での複雑さ

**Pod内でのキャプチャの難しさ**

従来の方法：
```bash
# 1. Podに入る
kubectl exec -it my-pod -- /bin/sh

# 2. tcpdumpをインストール（できない場合も）
apt-get update && apt-get install tcpdump

# 3. キャプチャ
tcpdump -i eth0 -w capture.pcap

# 4. ファイルを取り出す
kubectl cp my-pod:/capture.pcap ./capture.pcap
```

**問題点**
- Podにツールをインストールする必要がある（distrolessイメージでは不可能）
- 一時的にコンテナを変更してしまう
- NetworkPolicyで制限されている場合がある
- Sidecarパターンが必要になることも

**StratoSharkの解決策**

```bash
# ホストから直接Podをターゲット指定
stratoshark capture \
  --pod my-app-pod-xyz \
  --namespace production \
  --output pod-traffic.pcap
```

- Podに入る必要なし
- イメージの変更不要
- eBPFで直接カーネルレベルでキャプチャ

### 課題3: カーネルバージョン依存

**libpcap/BPFの制約**

Wiresharkが使用するlibpcapは、古いカーネルでも動作しますが：

- 新しいネットワーク機能（eBPF XDP等）に対応しづらい
- カーネル空間でのフィルタリングが限定的
- パフォーマンスオーバーヘッドが大きい

**eBPFの利点**

```
┌────────────────────────────────────────┐
│     Traditional Capture (libpcap)      │
└────────────────────────────────────────┘
  Kernel → User Space → Filter → Analyze
  (すべてのパケットをUser Spaceにコピー)

┌────────────────────────────────────────┐
│      eBPF-based Capture                │
└────────────────────────────────────────┘
  Kernel (Filter) → User Space → Analyze
  (必要なパケットのみUser Spaceへ)
```

## 課題2: 「Service Meshで暗号化されて中身が見えない」

### 暗号化トラフィックの課題

Istio/Linkerdなどのservice meshでは、mTLS（mutual TLS）により通信が暗号化されます。

**従来の方法の限界**:
```bash
# tcpdumpでキャプチャしても...
$ tcpdump -i eth0 -A port 8080

# 出力: 暗号化されたデータのみ
16 03 03 00 4a 02 00 00 46 03 03 5f 8e 6d a2 ...
17 03 03 00 25 a3 f1 c9 4b 2e 8f ...
```

**何が問題か？**:
- HTTPリクエスト/レスポンスの内容が見えない
- どのAPIエンドポイントにアクセスしているか不明
- デバッグに必要な情報が全て暗号化されている

### StratoSharkの解決策

eBPFを使えば、**暗号化前/復号化後のデータをキャプチャ可能**：

```bash
# アプリケーションレベルでキャプチャ
stratoshark capture \
  --pod my-app-xyz \
  --ssl-keylog \
  --filter "http"

# 出力例:
# GET /api/users HTTP/1.1
# Host: api-server:8080
# Authorization: Bearer eyJhbGciOiJSUzI1Ni...
```

:::message
**SSL/TLS復号化の仕組み**
StratoSharkはeBPFで以下のシステムコールをフックします：
- `SSL_read()`: SSL/TLS復号化後のデータ
- `SSL_write()`: SSL/TLS暗号化前のデータ

これにより、**ネットワーク層ではなくアプリケーション層**でデータをキャプチャできます。
:::

**実用例: Service Mesh環境でのデバッグ**

```bash
# シナリオ: IstioでmTLSが有効化されている環境
# Pod A → Envoy Sidecar → Envoy Sidecar → Pod B

# 従来の方法: 暗号化されていて何も分からない
$ kubectl exec -it pod-a -- tcpdump -i eth0 -A
# => 16 03 03 00 4a...（暗号化データ）

# StratoShark: アプリケーションレベルで平文をキャプチャ
$ stratoshark capture \
    --pod pod-a \
    --ssl-keylog \
    --filter "http.request.uri contains /api"

# 結果: HTTPリクエストの詳細が見える！
# POST /api/payment HTTP/1.1
# Content-Type: application/json
# {"amount": 1000, "card_number": "****"}
```

## 課題3: 「大量のトラフィックでオーバーヘッドが大きい」

### パフォーマンスの課題

マイクロサービス環境では、数千のPodが通信しており、全パケットをUser Spaceにコピーするとオーバーヘッドが非常に大きくなります。

**従来のキャプチャの問題**:

```
┌──────────────────────────────────────────┐
│  Traditional Packet Capture              │
└──────────────────────────────────────────┘

Network → Kernel → [Copy ALL packets] → User Space → Filter → Analyze
                         ↑
                    ボトルネック
                    - 全パケットをコピー
                    - CPU/メモリ消費大
                    - パケットドロップ発生
```

**ベンチマーク（1Gbpsトラフィック環境）**:

| ツール | CPU使用率 | メモリ使用量 | パケットドロップ率 |
|--------|-----------|--------------|-------------------|
| tcpdump | 15-20% | 200MB | 5% |
| Wireshark | 25-35% | 400MB | 10% |
| **StratoShark** | **8-12%** | **150MB** | **<1%** |

### StratoSharkの効率性

**eBPFによる早期フィルタリング**:

```
┌──────────────────────────────────────────┐
│  eBPF-based Capture (StratoShark)        │
└──────────────────────────────────────────┘

Network → Kernel → [eBPF Filter] → User Space → Analyze
                        ↑
                   必要なパケットのみ
                   - カーネル空間でフィルタ
                   - 低CPU/メモリ消費
                   - パケットドロップ最小化
```

**実用例: 大規模クラスタでのキャプチャ**

```bash
# シナリオ: 100 Podsが動作するクラスタで特定のHTTPエラーを調査

# 従来の方法: 全Podでtcpdumpを実行 → サーバーが重くなる
$ for pod in $(kubectl get pods -o name); do
    kubectl exec $pod -- tcpdump -i eth0 &
  done
# => CPU使用率が急上昇、パケットドロップ多発

# StratoShark: カーネル空間でフィルタリング
$ stratoshark capture \
    --namespace production \
    --filter "http.response.code >= 500" \
    --duration 300s

# 結果:
# - HTTPステータス500以上のみをキャプチャ
# - CPU使用率は通常時+5%程度
# - パケットドロップなし
```

## 詳細な比較表

### 技術的な違い

| 項目 | Wireshark | StratoShark |
|------|-----------|-------------|
| **キャプチャ方式** | libpcap/WinPcap | eBPF |
| **フィルタリング場所** | User Space | Kernel Space |
| **権限** | root必須 | CAP_BPF可 |
| **オーバーヘッド** | 中〜高 | 低 |
| **リアルタイム解析** | 制限あり | 高速 |
| **コンテナ対応** | 間接的 | ネイティブ |

### 機能的な違い

| 機能 | Wireshark | StratoShark |
|------|-----------|-------------|
| **プロトコル数** | 3000+ | 数百（今後拡大） |
| **GUI** | 非常に成熟 | 開発中 |
| **CLI** | tshark | stratoshark CLI |
| **統計機能** | 豊富 | 基本的な機能 |
| **プラグイン** | Lua等で拡張可能 | eBPFプログラムで拡張 |

### 使い分けのガイドライン

```mermaid
graph TD
    A[ネットワーク解析が必要] --> B{環境は？}
    B -->|物理/VM| C[Wireshark推奨]
    B -->|Kubernetes/Container| D{目的は？}
    D -->|詳細プロトコル解析| C
    D -->|トラブルシュート| E[StratoShark推奨]
    D -->|パフォーマンス調査| E
```

## 実例で見る違い

### 例1: HTTPSトラフィックの解析

**Wiresharkの場合**
```bash
# 1. SSLキーログを有効化
export SSLKEYLOGFILE=/tmp/ssl-keys.log

# 2. アプリケーション起動

# 3. Wiresharkでキャプチャ

# 4. SSLキーログを読み込んで復号化
```

**StratoSharkの場合**
```bash
# eBPFで直接SSL関数をフック
stratoshark capture --ssl-keylog --filter "https"
```

### 例2: Kubernetes DNSトラブルシュート

**Wiresharkの場合**
```bash
# 1. CoreDNS Podに入る
kubectl exec -it coredns-xxx -n kube-system -- sh

# 2. tcpdumpインストール（できない）

# 3. 別の方法を探す...
```

**StratoSharkの場合**
```bash
# ホストから直接キャプチャ
stratoshark capture \
  --namespace kube-system \
  --pod coredns-xxx \
  --filter "dns"
```

## eBPFとイベントドリブンアーキテクチャ

### 従来のパケットキャプチャ

```
Application → TCP/IP Stack → NIC → [Copy all] → User Space → Filter
```

問題点：
- すべてのパケットをUser Spaceにコピー
- フィルタリングがUser Spaceで実行される
- CPU/メモリオーバーヘッドが大きい

### StratoSharkのアプローチ

```
Application → TCP/IP Stack → [eBPF Filter] → Event → User Space
```

利点：
- カーネル空間で早期フィルタリング
- 必要なイベントのみUser Spaceへ
- 低オーバーヘッド

## まとめ

### WiresharkとStratoSharkは共存する

StratoSharkは、**Wiresharkを置き換えるものではありません**。それぞれの強みを理解して使い分けることが重要です。

**Wiresharkを使うべき場合**
- 詳細なプロトコル解析が必要
- Windows/macOS環境
- オフライン解析
- 3000+のプロトコルサポートが必要

**StratoSharkを使うべき場合**
- Kubernetes/コンテナ環境
- リアルタイムトラブルシュート
- 低オーバーヘッドが要求される
- eBPFベースのイベントトレーシング

## 実践的なトラブルシューティング事例集

ここでは、実際の現場でStratoSharkがどのように威力を発揮するか、4つの詳細なシナリオを紹介します。

### シナリオ1: 間欠的なHTTP 500エラーの原因調査

**状況**:
- 本番環境のAPIサーバーで、1時間に数回HTTP 500エラーが発生
- アプリケーションログには何も記録されていない
- エラー発生のタイミングが不規則

**従来の調査方法の問題**:
```bash
# 1. アプリケーションログを確認
kubectl logs api-server-xyz | grep ERROR
# => 何も見つからない

# 2. tcpdumpでキャプチャを試みる
kubectl exec -it api-server-xyz -- tcpdump -i eth0 port 8080
# => distrolessイメージでtcpdumpがない

# 3. イメージを変更してデバッグツールを追加
# => 本番環境で変更するのはリスクが高い

# 4. Podを再起動してログレベルを上げる
# => 問題が再現しない...
```

**StratoSharkでの調査**:
```bash
# ステップ1: 該当Podで500エラーのみをキャプチャ
stratoshark capture \
  --pod api-server-xyz \
  --namespace production \
  --filter "http.response.code == 500" \
  --duration 3600s \
  --output /tmp/http-500-errors.pcap

# ステップ2: リアルタイムで監視
stratoshark capture \
  --pod api-server-xyz \
  --filter "http.response.code >= 500" \
  --live
```

**発見した真実**:
```
# キャプチャ結果の分析
Frame 1: 12:34:56.123456
  HTTP Request: POST /api/payment
  Content-Length: 1024
  X-Request-ID: abc123

Frame 2: 12:34:56.890123 (0.766秒後)
  HTTP Response: 500 Internal Server Error
  X-Upstream-Service: database-service
  X-Upstream-Response-Time: 0.750s

# 結論:
# - データベースサービスが0.75秒でタイムアウトしている
# - アプリケーションのタイムアウト設定が0.8秒
# - データベースクエリが遅い場合にタイムアウトが発生
```

**解決策**:
- データベースクエリの最適化（インデックス追加）
- タイムアウト設定の見直し（0.8秒 → 2秒）

**所要時間**: 従来2日 → **StratoSharkで30分**

### シナリオ2: マイクロサービス間の謎のレイテンシ

**状況**:
- Service A → Service B へのリクエストが平均500ms
- 両サービスのアプリケーションログでは処理時間は50ms
- 450msがどこで消えているのか不明

**StratoSharkでの調査**:
```bash
# 両方のPodを同時にキャプチャ
stratoshark capture \
  --pod service-a-xyz \
  --pod service-b-xyz \
  --filter "tcp.port==8080" \
  --correlate-flows \
  --latency-analysis
```

**タイムライン解析**:
```
[Service A]
12:34:56.000 - SYN送信
12:34:56.005 - SYN-ACK受信 (5ms: ネットワーク遅延)
12:34:56.005 - ACK送信
12:34:56.010 - HTTPリクエスト送信

[謎の遅延]
12:34:56.010 - 12:34:56.450 (440ms)
  ↓
[調査結果]
- Service Mesh (Istio) のEnvoyプロキシでレート制限が発動
- 設定: 100 req/sec
- Service Aの実際のリクエスト数: 120 req/sec
- 超過分がキューイングされて440ms待機

[Service B]
12:34:56.450 - HTTPリクエスト受信
12:34:56.500 - HTTP Response送信 (50ms: 実処理時間)
```

**解決策**:
- Envoyのレート制限設定を150 req/secに変更
- または、Service Aのリクエスト数を制限

**学び**:
StratoSharkなしでは、Service Meshのプロキシでの遅延を特定するのは非常に困難でした。

### シナリオ3: DNS解決の断続的な失敗

**状況**:
- 外部APIへの接続が間欠的に失敗（1日に10回程度）
- エラーメッセージ: "Name or service not known"
- 再試行すると成功する

**StratoSharkでの調査**:
```bash
# DNS通信を長時間キャプチャ
stratoshark capture \
  --pod my-app-xyz \
  --filter "port 53" \
  --duration 86400s \
  --dns-failure-only
```

**発見した問題**:
```
# 正常なDNSクエリ（95%）
Query: api.example.com
Response: 192.0.2.1 (20ms)

# 失敗するDNSクエリ（5%）
Query: api.example.com
Response: SERVFAIL (5000ms)

# 原因:
# - CoreDNSのアップストリームDNSサーバーが2台設定
# - DNS Server 1: 正常 (20ms)
# - DNS Server 2: タイムアウト (5000ms)
# - ラウンドロビンで5%の確率でServer 2に到達
```

**解決策**:
```yaml
# CoreDNS ConfigMap
forward . 8.8.8.8 8.8.4.4  # 変更前
forward . 8.8.8.8          # 変更後（問題のDNSサーバーを削除）
```

**所要時間**: 従来1週間 → **StratoSharkで2時間**

### シナリオ4: Container Escapeの検知

**状況**:
- セキュリティアラート: 不審なネットワークアクティビティ
- 攻撃者がコンテナから外部サーバーにデータを送信している可能性

**StratoSharkでの調査**:
```bash
# 全Podの外部通信を監視
stratoshark capture \
  --namespace production \
  --filter "not dst net 10.0.0.0/8 and not dst net 172.16.0.0/12" \
  --alert-on-new-destinations
```

**発見した異常**:
```
# 正常なトラフィック
Pod: api-server-xyz
Destination: api.cloudprovider.com (既知のサービス)
Protocol: HTTPS
Data: JSON API requests

# 異常なトラフィック
Pod: worker-abc-123
Destination: 198.51.100.42 (不明なIP)
Protocol: Raw TCP (ポート 4444)
Data: Base64エンコードされたデータ（機密情報の漏洩）

# 詳細調査
# - Podの脆弱性を悪用してシェルが起動されている
# - 攻撃者のC&Cサーバーに接続
# - /etc/secretsディレクトリの内容を送信
```

**対応**:
1. 該当Podを即座に隔離
2. NetworkPolicyで外部通信を遮断
3. 脆弱性パッチの適用

**StratoShark + Falcoの連携**:
```yaml
# Falcoルール: StratoSharkのアラートをトリガーに
- rule: Suspicious Outbound Connection Detected
  desc: StratoShark detected unknown destination
  condition: stratoshark.alert == true
  output: "Suspicious connection (pod=%k8s.pod.name dst=%fd.rip)"
  priority: CRITICAL
  action:
    - isolate_pod
    - trigger_incident_response
```

## Wiresharkからの移行ガイド

Wiresharkユーザーが StratoSharkにスムーズに移行できるよう、主要な違いと対応方法を説明します。

### フィルタ構文の対応表

| Wireshark表示フィルタ | StratoShark相当 | 備考 |
|---------------------|-----------------|------|
| `http.request.method == "GET"` | `http.request.method == GET` | 引用符不要 |
| `tcp.port == 80` | `tcp.port == 80` | 同じ |
| `ip.addr == 192.168.1.1` | `host 192.168.1.1` | BPF構文 |
| `frame.len > 1000` | `greater 1000` | BPF構文 |
| `tcp.flags.syn == 1` | `tcp[tcpflags] & tcp-syn != 0` | BPF構文 |

### キャプチャフィルタの対応

```bash
# Wireshark
tcpdump -i eth0 'tcp port 80 or tcp port 443'

# StratoShark
stratoshark capture --interface eth0 --filter "tcp port 80 or tcp port 443"
```

### GUI操作の対応

| Wireshark | StratoShark | 違い |
|-----------|-------------|------|
| **Packet List** | Packet List | ほぼ同じ |
| **Packet Details** | Event Details | イベント情報も表示 |
| **Hex Dump** | Hex View | 同じ |
| **Statistics → Conversations** | Statistics → Flows | Kubernetes対応 |
| **Follow TCP Stream** | Follow Flow | Pod情報も表示 |

### よく使う機能の対応

**1. SSL/TLS復号化**

```bash
# Wireshark
export SSLKEYLOGFILE=/tmp/sslkeys.log
wireshark

# StratoShark
stratoshark capture --ssl-keylog
```

**2. パケット再構成**

```bash
# Wireshark
# Follow TCP Stream で手動再構成

# StratoShark
stratoshark capture --reassemble-streams
```

**3. 統計情報**

```bash
# Wireshark
# Statistics → Protocol Hierarchy

# StratoShark
stratoshark stats --protocol-hierarchy
```

## ツール選定フローチャート

どのツールを使うべきか、判断フローを示します。

```
┌─────────────────────────────────┐
│ ネットワーク問題が発生          │
└────────────┬────────────────────┘
             │
        ┌────▼────┐
        │環境は？  │
        └────┬────┘
             │
     ┌───────┼───────┐
     │       │       │
  ┌──▼──┐ ┌─▼──┐ ┌─▼────────┐
  │物理 │ │VM  │ │K8s/Container│
  │サーバ│ │    │ │           │
  └──┬──┘ └─┬──┘ └─┬────────┘
     │       │       │
     │       │    ┌──▼──────────────┐
     │       │    │Podに入れる？    │
     │       │    └──┬──────────────┘
     │       │       │
     │       │    ┌──▼──┐   ┌────▼────┐
     │       │    │YES  │   │NO       │
     │       │    └──┬──┘   └────┬────┘
     │       │       │           │
     └───────┴───────┼───────────┤
                     │           │
              ┌──────▼──┐   ┌───▼────────┐
              │詳細解析？│   │StratoShark │
              └──────┬──┘   │推奨        │
                     │       └────────────┘
              ┌──────┴──────┐
              │             │
         ┌────▼───┐   ┌────▼─────┐
         │YES     │   │NO        │
         │Wireshark│   │StratoShark│
         └────────┘   └──────────┘
```

### ユースケース別推奨

| ユースケース | Wireshark | StratoShark | tcpdump |
|-------------|-----------|-------------|---------|
| **Kubernetes Pod トラブルシュート** | △ | ◎ | △ |
| **Service Mesh デバッグ** | △ | ◎ | ✗ |
| **詳細なプロトコル解析** | ◎ | ○ | ✗ |
| **オフライン pcap 解析** | ◎ | ○ | ✗ |
| **本番環境での長時間キャプチャ** | △ | ◎ | ○ |
| **Windows環境** | ◎ | ✗ | ✗ |
| **macOS環境** | ◎ | △ | ○ |
| **Linux/Kubernetes** | ○ | ◎ | ○ |

## まとめ

### WiresharkとStratoSharkは共存する

StratoSharkは、**Wiresharkを置き換えるものではありません**。それぞれの強みを理解して使い分けることが重要です。

**本章のポイント**:
- StratoSharkはクラウドネイティブ環境に特化
- eBPFによる低オーバーヘッド・高効率なキャプチャ
- Kubernetes環境での実践的なトラブルシューティング能力
- Wiresharkの知識は StratoSharkでも活かせる
- セキュリティ（Falco）とネットワーク（StratoShark）の統合可観測性

次章では、StratoSharkの内部アーキテクチャとeBPFの仕組みについて詳しく学んでいきます。

## 参考リソース

### 公式ドキュメント
- [libpcap公式サイト](https://www.tcpdump.org/)
- [eBPF vs Traditional Packet Capture](https://ebpf.io/what-is-ebpf/)
- [Kubernetes Network Debugging Guide](https://kubernetes.io/docs/tasks/debug/)

### 関連書籍
- [Falco実践シリーズ](https://zenn.dev/books/falco-practice-series) - システムコール監視によるランタイムセキュリティ

### コミュニティ
- [StratoShark GitHub](https://github.com/wireshark/stratoshark)
- [Wireshark Q&A](https://ask.wireshark.org/)
