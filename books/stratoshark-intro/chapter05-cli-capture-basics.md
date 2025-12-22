---
title: "CLIでのキャプチャ ― stratoshark capture の基本操作"
---

# CLIでのキャプチャ

## 本章の目的

`stratoshark capture` コマンドを使った実践的なキャプチャ操作を学びます。フィルタリング、出力制御、リアルタイム解析など、SRE業務で必要となる実践的なテクニックを解説します。

## 基本的なキャプチャ

### 最もシンプルなキャプチャ

```bash
# 5秒間キャプチャしてファイルに保存
sudo stratoshark capture --duration 5s --output capture.pcap
```

**実行結果**:
```
[2025-01-10 10:15:32] Starting capture on eth0
[2025-01-10 10:15:32] eBPF programs loaded successfully
[2025-01-10 10:15:37] Capture complete
[2025-01-10 10:15:37] Captured 1,234 packets (1.2 MB)
[2025-01-10 10:15:37] Saved to: capture.pcap
```

### インターフェース指定

```bash
# 特定のネットワークインターフェースを指定
sudo stratoshark capture --interface docker0 --duration 10s
```

**利用可能なインターフェース一覧**:
```bash
# インターフェース一覧を表示
stratoshark interfaces

# 出力例:
# 1. lo (Loopback, 127.0.0.1)
# 2. eth0 (Ethernet, 192.168.1.100)
# 3. docker0 (Bridge, 172.17.0.1)
# 4. cali0a1b2c3 (Calico, 10.244.1.5)
```

---

## フィルタリング

### BPF（Berkeley Packet Filter）フィルタ

Wiresharkと互換性のあるBPFフィルタが使用できます。

#### ポート指定

```bash
# HTTP/HTTPS トラフィックのみキャプチャ
sudo stratoshark capture \
  --filter "tcp port 80 or tcp port 443" \
  --duration 30s \
  --output web-traffic.pcap
```

#### ホスト指定

```bash
# 特定のIPアドレスとの通信をキャプチャ
sudo stratoshark capture \
  --filter "host 192.168.1.100" \
  --output host-traffic.pcap
```

#### 複合フィルタ

```bash
# 192.168.1.100へのHTTPSトラフィックのみ
sudo stratoshark capture \
  --filter "host 192.168.1.100 and tcp port 443" \
  --output specific-https.pcap
```

### よく使うBPFフィルタ例

| 目的 | フィルタ |
|------|----------|
| HTTP/HTTPS | `tcp port 80 or tcp port 443` |
| DNS | `udp port 53 or tcp port 53` |
| SSH | `tcp port 22` |
| ICMP (ping) | `icmp` |
| 特定サブネット | `net 192.168.1.0/24` |
| 特定プロトコル | `tcp` / `udp` / `icmp` |
| 送信パケットのみ | `src host 192.168.1.100` |
| 受信パケットのみ | `dst host 192.168.1.100` |

---

## 出力制御

### ファイルサイズの制限

```bash
# 100MBごとに新しいファイルを作成（ローテーション）
sudo stratoshark capture \
  --output traffic.pcap \
  --rotate-size 100M \
  --rotate-files 5  # 最大5ファイル保持
```

**生成されるファイル**:
```
traffic.pcap
traffic.pcap.1
traffic.pcap.2
traffic.pcap.3
traffic.pcap.4
```

### 時間ベースのローテーション

```bash
# 1時間ごとに新しいファイルを作成
sudo stratoshark capture \
  --output /var/log/captures/traffic.pcap \
  --rotate-time 1h \
  --rotate-files 24  # 24時間分保持
```

### 圧縮保存

```bash
# キャプチャファイルを圧縮して保存
sudo stratoshark capture \
  --output traffic.pcap.gz \
  --compress gzip \
  --duration 1h
```

**サポートされる圧縮形式**:
- `gzip` - 標準的な圧縮（おすすめ）
- `bzip2` - 高圧縮率
- `zstd` - 高速圧縮

---

## リアルタイム解析

### ライブモード

```bash
# キャプチャ内容をリアルタイムで表示
sudo stratoshark live --interface eth0
```

**出力例**:
```
Time          Source           Destination      Protocol  Length  Info
10:15:32.123  192.168.1.100    8.8.8.8         DNS        74      Standard query A google.com
10:15:32.145  8.8.8.8          192.168.1.100   DNS        90      Standard query response
10:15:32.234  192.168.1.100    172.217.175.46  TCP        66      [SYN] Seq=0
10:15:32.256  172.217.175.46   192.168.1.100   TCP        66      [SYN, ACK] Seq=0 Ack=1
```

### 統計情報の表示

```bash
# 1秒ごとに統計を表示
sudo stratoshark capture \
  --interface eth0 \
  --stats 1s
```

**出力例**:
```
[2025-01-10 10:15:32] Packets: 123    Bytes: 45.6 KB   TCP: 67%   UDP: 28%   ICMP: 5%
[2025-01-10 10:15:33] Packets: 145    Bytes: 52.1 KB   TCP: 65%   UDP: 30%   ICMP: 5%
[2025-01-10 10:15:34] Packets: 138    Bytes: 48.3 KB   TCP: 70%   UDP: 25%   ICMP: 5%
```

---

## スナップレングス（Snaplen）

パケットのキャプチャサイズを制限することで、ストレージを節約できます。

### デフォルト（全体をキャプチャ）

```bash
# デフォルト: パケット全体をキャプチャ（65535バイト）
sudo stratoshark capture --snaplen 65535
```

### ヘッダのみキャプチャ

```bash
# 最初の96バイトのみ（ほとんどのヘッダを含む）
sudo stratoshark capture --snaplen 96 --output headers-only.pcap
```

**推奨設定**:

| ユースケース | Snaplen | 説明 |
|-------------|---------|------|
| **完全キャプチャ** | 65535 | パケット全体（ペイロード含む） |
| **ヘッダ解析** | 96-128 | TCP/IP/HTTPヘッダまで |
| **接続追跡** | 64 | TCP/IPヘッダのみ |
| **統計のみ** | 54 | Ethernetフレームヘッダのみ |

---

## バッファリングとパフォーマンス

### バッファサイズの調整

```bash
# バッファサイズを64MBに設定（高トラフィック環境）
sudo stratoshark capture \
  --buffer-size 64M \
  --interface eth0
```

**デフォルト設定**:
- 標準: 16MB
- 高トラフィック: 64MB以上推奨
- 低リソース環境: 4-8MB

### パケットドロップの確認

```bash
# パケットドロップ統計を含めて実行
sudo stratoshark capture \
  --duration 60s \
  --verbose
```

**出力に含まれる情報**:
```
Capture Statistics:
  Packets received: 10,234
  Packets dropped by kernel: 0
  Packets dropped by interface: 0
  Buffer utilization: 45%
```

---

## Kubernetes環境でのキャプチャ

### 特定Podのトラフィックをキャプチャ

```bash
# KubernetesのPodを指定してキャプチャ
sudo stratoshark capture \
  --k8s-pod my-app-pod-12345 \
  --k8s-namespace production \
  --duration 5m \
  --output pod-traffic.pcap
```

### コンテナインターフェース指定

```bash
# コンテナのネットワークインターフェースを直接指定
sudo stratoshark capture \
  --interface veth1a2b3c4 \
  --filter "tcp port 8080"
```

### Kubernetesクラスタ全体のキャプチャ

```bash
# DaemonSetとして実行中のStratoSharkから取得
kubectl exec -n stratoshark stratoshark-xxxxx -- \
  stratoshark capture \
    --duration 10s \
    --output /tmp/capture.pcap

# ファイルをローカルにコピー
kubectl cp stratoshark/stratoshark-xxxxx:/tmp/capture.pcap ./cluster-traffic.pcap
```

---

## 実践例

### 例1: HTTPトラフィックの監視

```bash
#!/bin/bash
# HTTP/HTTPSトラフィックを1時間ごとにローテーションしてキャプチャ

sudo stratoshark capture \
  --interface eth0 \
  --filter "tcp port 80 or tcp port 443" \
  --output /var/log/stratoshark/http-traffic.pcap \
  --rotate-time 1h \
  --rotate-files 24 \
  --compress gzip \
  --stats 10s
```

### 例2: DNS解決の追跡

```bash
#!/bin/bash
# DNS クエリとレスポンスをキャプチャ

sudo stratoshark capture \
  --interface eth0 \
  --filter "udp port 53 or tcp port 53" \
  --output dns-queries.pcap \
  --duration 30m \
  --snaplen 512  # DNSメッセージは通常512バイト以下
```

### 例3: 特定アプリケーションのトラフィック

```bash
#!/bin/bash
# アプリケーションが使用するポートをキャプチャ

# アプリケーションのPIDを取得
APP_PID=$(pgrep -f my-application)

# そのPIDが使用しているポートを特定
PORTS=$(ss -tulpn | grep $APP_PID | awk '{print $5}' | cut -d: -f2 | tr '\n' ' ')

# フィルタを動的に生成
FILTER="tcp port ${PORTS// / or tcp port }"

# キャプチャ実行
sudo stratoshark capture \
  --filter "$FILTER" \
  --output app-traffic.pcap \
  --duration 1h
```

### 例4: パフォーマンス問題の調査

```bash
#!/bin/bash
# 高レイテンシの接続を特定するための詳細キャプチャ

sudo stratoshark capture \
  --interface eth0 \
  --filter "tcp" \
  --output performance-debug.pcap \
  --duration 5m \
  --buffer-size 128M \
  --snaplen 65535 \
  --stats 1s \
  --verbose
```

---

## CLIスクリプト化

### systemdサービスとして実行

```ini
# /etc/systemd/system/stratoshark-capture.service
[Unit]
Description=StratoShark Continuous Capture
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/stratoshark capture \
  --interface eth0 \
  --output /var/log/stratoshark/traffic.pcap \
  --rotate-time 1h \
  --rotate-files 24 \
  --compress gzip
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# サービスを有効化
sudo systemctl enable stratoshark-capture
sudo systemctl start stratoshark-capture

# ステータス確認
sudo systemctl status stratoshark-capture
```

### cronでの定期実行

```bash
# crontabに追加
# 毎日午前2時に1時間キャプチャ
0 2 * * * /usr/local/bin/stratoshark capture \
  --interface eth0 \
  --output /var/log/stratoshark/daily-$(date +\%Y\%m\%d).pcap.gz \
  --duration 1h \
  --compress gzip
```

---

## トラブルシューティング

### 問題1: パケットドロップが発生する

**症状**:
```
Packets dropped by kernel: 1,234 (12.3%)
```

**解決策**:
```bash
# バッファサイズを増やす
sudo stratoshark capture --buffer-size 128M

# スナップレングスを減らす（ヘッダのみ）
sudo stratoshark capture --snaplen 96

# 不要なフィルタを追加してトラフィックを減らす
sudo stratoshark capture --filter "tcp port 80 or tcp port 443"
```

### 問題2: ディスクが満杯になる

**症状**:
```
Error: No space left on device
```

**解決策**:
```bash
# ローテーションとファイル数制限を設定
sudo stratoshark capture \
  --output traffic.pcap \
  --rotate-size 100M \
  --rotate-files 10 \
  --compress gzip

# 古いキャプチャファイルを自動削除するスクリプト
find /var/log/stratoshark -name "*.pcap*" -mtime +7 -delete
```

### 問題3: 権限エラー

**症状**:
```
Error: Operation not permitted
```

**解決策**:
```bash
# 方法1: sudoを使用
sudo stratoshark capture

# 方法2: CAP_NET_RAW capabilityを付与
sudo setcap cap_net_raw,cap_net_admin=eip $(which stratoshark)
stratoshark capture  # sudoなしで実行可能
```

---

## ベストプラクティス

### 1. フィルタを積極的に使う

**❌ 悪い例**:
```bash
# すべてのトラフィックをキャプチャ（ディスク消費大）
sudo stratoshark capture --duration 24h
```

**✅ 良い例**:
```bash
# 必要なトラフィックだけをフィルタ
sudo stratoshark capture \
  --filter "tcp port 80 or tcp port 443" \
  --duration 24h
```

### 2. ローテーションを設定する

**❌ 悪い例**:
```bash
# 単一の巨大ファイル（管理困難）
sudo stratoshark capture --output huge.pcap --duration 7d
```

**✅ 良い例**:
```bash
# 時間ベースでローテーション
sudo stratoshark capture \
  --output traffic.pcap \
  --rotate-time 1h \
  --rotate-files 168  # 1週間分
```

### 3. 圧縮を有効にする

**❌ 悪い例**:
```bash
# 非圧縮（ストレージ消費大）
sudo stratoshark capture --output capture.pcap
```

**✅ 良い例**:
```bash
# gzip圧縮（通常70-80%削減）
sudo stratoshark capture --output capture.pcap.gz --compress gzip
```

### 4. スナップレングスを適切に設定

**❌ 悪い例**:
```bash
# 常に全体をキャプチャ（不要なペイロード含む）
sudo stratoshark capture --snaplen 65535
```

**✅ 良い例**:
```bash
# ヘッダ解析のみなら96バイトで十分
sudo stratoshark capture --snaplen 96
```

---

## まとめ

本章では、`stratoshark capture` コマンドの実践的な使い方を学びました：

✅ **基本操作**: インターフェース指定、期間指定、出力制御
✅ **フィルタリング**: BPFフィルタを使った効率的なキャプチャ
✅ **出力制御**: ローテーション、圧縮、スナップレングス
✅ **リアルタイム解析**: ライブモード、統計表示
✅ **Kubernetes統合**: Pod単位でのキャプチャ
✅ **実践例**: HTTPトラフィック監視、DNS追跡、パフォーマンスデバッグ
✅ **自動化**: systemdサービス、cron統合
✅ **ベストプラクティス**: 効率的で保守しやすい設定

次章では、GUIでの解析方法を学びます。WiresharkライクなUIで、キャプチャデータをより深く分析する手法を解説します。
