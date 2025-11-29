---
title: "内部アーキテクチャ ― eBPFとイベントドリブンの設計"
---

# 内部アーキテクチャ

## 本章の目的

StratoSharkがどのように動作しているのか、内部アーキテクチャとeBPFの仕組みを理解します。SRE/Kubernetesエンジニア向けに、必要な知識を簡潔に解説します。

## eBPFとは？（5分で理解する）

### eBPFの基本概念

**eBPF（extended Berkeley Packet Filter）** は、Linuxカーネル内で安全にプログラムを実行できる革新的な技術です。

```
┌─────────────────────────────────────────┐
│         User Space                      │
│  ┌──────────────────────────────────┐   │
│  │  Application (StratoShark)       │   │
│  └────────────┬─────────────────────┘   │
│               │ BPF Maps (Data)         │
└───────────────┼─────────────────────────┘
                ↕
┌───────────────┼─────────────────────────┐
│  Kernel Space │                         │
│  ┌────────────▼─────────────────────┐   │
│  │  eBPF Program (Verified)         │   │
│  │  - Network Events                │   │
│  │  - System Calls                  │   │
│  │  - File Operations               │   │
│  └────────────┬─────────────────────┘   │
│               │                         │
│  ┌────────────▼─────────────────────┐   │
│  │  Linux Kernel Functions          │   │
│  │  (Socket, TCP/IP Stack, etc.)    │   │
│  └──────────────────────────────────┘   │
└─────────────────────────────────────────┘
```

### なぜeBPFが革新的なのか？

従来の方法との比較：

| 方式 | 実行場所 | 安全性 | 動的性 |
|------|----------|--------|--------|
| **カーネルモジュール** | Kernel Space | 低（クラッシュリスク） | 低（再起動必要） |
| **User Space** | User Space | 高 | 高（遅い） |
| **eBPF** | Kernel Space | 高（Verifier） | 高（動的） |

### eBPFの安全性を支える仕組み

eBPFプログラムは、ロード時に**eBPF Verifier**によって検証されます：

```
┌──────────────────────────────────────────┐
│  eBPF Program Loading                    │
└──────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────┐
│  eBPF Verifier                           │
│  ✓ 無限ループがないか                      │
│  ✓ メモリアクセスが安全か                  │
│  ✓ 許可された関数のみ呼び出すか             │
└──────────────────────────────────────────┘
         │
    ┌────┴────┐
    ▼         ▼
  ✓ OK      ✗ NG
    │         │
    │         └─→ [Rejected]
    ▼
┌──────────────────────────────────────────┐
│  JIT Compilation                         │
│  (機械語に変換)                           │
└──────────────────────────────────────────┘
    │
    ▼
┌──────────────────────────────────────────┐
│  Kernel Space Execution                  │
└──────────────────────────────────────────┘
```

## StratoSharkのアーキテクチャ

### 全体像

```
┌─────────────────────────────────────────────────────────────┐
│                    StratoShark Architecture                  │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    User Space                                │
│                                                               │
│  ┌──────────────┐         ┌──────────────┐                  │
│  │     GUI      │         │     CLI      │                  │
│  │  (Qt-based)  │         │   Commands   │                  │
│  └──────┬───────┘         └──────┬───────┘                  │
│         │                        │                          │
│         └────────────┬───────────┘                          │
│                      ▼                                       │
│         ┌────────────────────────┐                          │
│         │  Analysis Engine       │                          │
│         │  - Protocol Dissectors │                          │
│         │  - Statistics          │                          │
│         │  - Filtering           │                          │
│         └────────────┬───────────┘                          │
│                      │                                       │
│         ┌────────────▼───────────┐                          │
│         │  Capture Engine        │                          │
│         │  - Event Processing    │                          │
│         │  - Buffer Management   │                          │
│         │  - BPF Map Handling    │                          │
│         └────────────┬───────────┘                          │
└──────────────────────┼──────────────────────────────────────┘
                       │ BPF Maps
┌──────────────────────┼──────────────────────────────────────┐
│   Kernel Space       ▼                                       │
│                                                               │
│         ┌────────────────────────┐                          │
│         │  eBPF Programs         │                          │
│         ├────────────────────────┤                          │
│         │  • kprobe              │                          │
│         │  • tracepoint          │                          │
│         │  • XDP                 │                          │
│         │  • socket filter       │                          │
│         └────────────┬───────────┘                          │
│                      │                                       │
│         ┌────────────▼───────────┐                          │
│         │  Linux Kernel          │                          │
│         │  - Network Stack       │                          │
│         │  - Socket Layer        │                          │
│         │  - Device Drivers      │                          │
│         └────────────────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

### 主要コンポーネント

#### 1. Capture Engine（キャプチャエンジン）

**役割**
- eBPFプログラムの管理
- イベントの収集
- BPF Mapからのデータ読み取り

**実装例**（概念）
```c
// eBPFプログラムの例（簡略版）
BPF_HASH(packet_map, u32, struct packet_info);

int capture_packet(struct __sk_buff *skb) {
    struct packet_info info = {};

    // パケット情報を取得
    info.timestamp = bpf_ktime_get_ns();
    info.len = skb->len;
    info.ifindex = skb->ifindex;

    // User Spaceに送信
    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU,
                          &info, sizeof(info));

    return 0;
}
```

#### 2. Analysis Engine（解析エンジン）

**役割**
- プロトコル解析（dissection）
- パケット再構成
- 統計情報の生成
- フィルタリング

**対応プロトコル（一部）**
- Layer 2: Ethernet, VLAN
- Layer 3: IP, IPv6, ICMP
- Layer 4: TCP, UDP
- Layer 7: HTTP, DNS, TLS

#### 3. Visualization（可視化）

**役割**
- GUI/CLIでの表示
- カラーリング
- カスタムビュー

## eBPFプログラムの種類

StratoSharkは複数のeBPFプログラムタイプを活用しています。

### 1. Socket Filter

**用途**: ソケットレベルでのパケットキャプチャ

```c
SEC("socket")
int socket_filter(struct __sk_buff *skb) {
    // ソケットを通過するパケットをキャプチャ
    return 0; // 0 = accept, !0 = drop
}
```

### 2. kprobe / kretprobe

**用途**: カーネル関数のフック

```c
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    // TCP接続の開始を検知
    return 0;
}
```

### 3. tracepoint

**用途**: 安定したカーネルイベントのトレース

```c
SEC("tracepoint/net/netif_receive_skb")
int trace_netif_receive(struct trace_event_raw_netif_receive_skb *ctx) {
    // パケット受信イベント
    return 0;
}
```

### 4. XDP（eXpress Data Path）

**用途**: 超高速パケット処理

```c
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    // NICドライバ直後でパケット処理
    return XDP_PASS; // XDP_DROP, XDP_TX, XDP_REDIRECT
}
```

## イベント収集の流れ

### ステップ1: eBPFプログラムのロード

```bash
# StratoShark起動時
stratoshark capture --interface eth0
```

内部動作：
```
1. eBPFプログラムをコンパイル（またはロード）
2. Verifierによる検証
3. JITコンパイル
4. カーネルにアタッチ
```

### ステップ2: イベントの捕捉

```
Network Packet → Kernel → eBPF Program → BPF Map
```

### ステップ3: User Spaceへの転送

eBPFプログラムは以下の方法でデータを転送：

| 方法 | 特徴 | 用途 |
|------|------|------|
| **BPF Maps** | Key-Value Store | 集約データ、状態管理 |
| **Perf Events** | Ring Buffer | 高頻度イベント |
| **Ring Buffer** | 新しいRing Buffer実装 | 低レイテンシ |

### ステップ4: 解析と表示

```
User Space → Analysis Engine → Visualization
```

## クラウドネイティブ可観測性との親和性

### Kubernetes環境での動作

StratoSharkは、Kubernetesのネットワークモデルを理解しています：

```
┌─────────────────────────────────────────┐
│  Node                                   │
│  ┌───────────────────────────────────┐  │
│  │  Pod A (Namespace: prod)          │  │
│  │  ┌─────────────┐                  │  │
│  │  │  Container  │                  │  │
│  │  └─────────────┘                  │  │
│  │         │                         │  │
│  │         ▼ (eBPF Hook)             │  │
│  │  ┌─────────────┐                  │  │
│  │  │   veth0     │                  │  │
│  │  └─────────────┘                  │  │
│  └──────────┬────────────────────────┘  │
│             │                           │
│  ┌──────────▼────────────────────────┐  │
│  │   CNI Bridge (cni0)               │  │
│  │   eBPF Programs Attached          │  │
│  └──────────┬────────────────────────┘  │
│             │                           │
│  ┌──────────▼────────────────────────┐  │
│  │   Host Network (eth0)             │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### OpenTelemetryとの統合

StratoSharkのデータは、OpenTelemetry形式でエクスポート可能：

```yaml
# 例: OTel Collector への送信
exporters:
  - type: otlp
    endpoint: otel-collector:4317
    metrics:
      - packet_count
      - bytes_transferred
      - latency
```

## パフォーマンス特性

### オーバーヘッドの比較

| ツール | CPU使用率 | メモリ使用量 | レイテンシ |
|--------|-----------|--------------|-----------|
| **tcpdump** | 中 (10-15%) | 中 | 中 |
| **Wireshark** | 高 (20-30%) | 高 | 高 |
| **StratoShark** | 低 (5-10%) | 低 | 低 |

:::message
**ベンチマーク条件**
- 1Gbps ネットワークトラフィック
- HTTP/HTTPSトラフィック混在
- フィルタ適用時
:::

### なぜ低オーバーヘッドなのか？

1. **カーネル空間でのフィルタリング**
   - 不要なパケットはUser Spaceに渡さない

2. **ゼロコピー技術**
   - BPF Mapsを使った効率的なデータ転送

3. **イベントドリブン**
   - 必要なイベントのみ捕捉

## eBPFプログラムの実例

StratoSharkがどのようにeBPFを活用しているか、実際のコード例で見ていきましょう。

### 例1: HTTPパケットのキャプチャ

```c
// eBPFプログラム: HTTP GETリクエストを検出
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// BPF Map定義: HTTPイベントを保存
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} http_events SEC(".maps");

// HTTPリクエスト情報
struct http_request {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u64 timestamp;
    char method[8];  // GET, POST, etc.
};

SEC("socket")
int capture_http(struct __sk_buff *skb) {
    // Ethernetヘッダーのパース
    struct ethhdr *eth = bpf_hdr_pointer(skb);
    if (eth->h_proto != htons(ETH_P_IP))
        return 0;

    // IPヘッダーのパース
    struct iphdr *ip = (void *)(eth + 1);
    if (ip->protocol != IPPROTO_TCP)
        return 0;

    // TCPヘッダーのパース
    struct tcphdr *tcp = (void *)(ip + 1);

    // HTTPポート（80, 8080）のチェック
    if (tcp->dest != htons(80) && tcp->dest != htons(8080))
        return 0;

    // HTTPペイロードのチェック
    char *payload = (void *)(tcp + 1);

    // "GET " または "POST " で始まるかチェック
    if (payload[0] == 'G' && payload[1] == 'E' &&
        payload[2] == 'T' && payload[3] == ' ') {

        // イベント情報を構築
        struct http_request req = {0};
        req.src_ip = ip->saddr;
        req.dst_ip = ip->daddr;
        req.src_port = ntohs(tcp->source);
        req.dst_port = ntohs(tcp->dest);
        req.timestamp = bpf_ktime_get_ns();
        __builtin_memcpy(req.method, "GET", 3);

        // User Spaceに送信
        bpf_perf_event_output(skb, &http_events, BPF_F_CURRENT_CPU,
                              &req, sizeof(req));
    }

    return 0;  // パケットを通す
}

char _license[] SEC("license") = "GPL";
```

### 例2: TCP接続の追跡

```c
// eBPFプログラム: TCP接続を追跡
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// BPF Map: アクティブなTCP接続を保存
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u64);    // connection_id
    __type(value, struct tcp_connection);
} active_connections SEC(".maps");

struct tcp_connection {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u64 start_time;
    u64 bytes_sent;
    u64 bytes_received;
    u8 state;  // SYN_SENT, ESTABLISHED, etc.
};

// kprobe: tcp_v4_connect をフック
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    // ソケット情報を取得
    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    // connection_id を生成（src_ip + src_port の組み合わせ）
    u64 conn_id = ((u64)saddr << 32) | sport;

    // 接続情報を作成
    struct tcp_connection conn = {0};
    conn.src_ip = saddr;
    conn.dst_ip = daddr;
    conn.src_port = sport;
    conn.dst_port = dport;
    conn.start_time = bpf_ktime_get_ns();
    conn.state = 1;  // SYN_SENT

    // BPF Mapに保存
    bpf_map_update_elem(&active_connections, &conn_id, &conn, BPF_ANY);

    return 0;
}

// kprobe: tcp_v4_do_rcv をフック（データ受信）
SEC("kprobe/tcp_v4_do_rcv")
int trace_tcp_rcv(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

    u64 conn_id = ... // connection_id を取得

    // 既存の接続情報を取得
    struct tcp_connection *conn = bpf_map_lookup_elem(&active_connections, &conn_id);
    if (conn) {
        // 受信バイト数を更新
        u32 len = BPF_CORE_READ(skb, len);
        conn->bytes_received += len;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
```

## BPF Mapsの詳細

BPF MapsはeBPFプログラムとUser Spaceの間でデータをやり取りする仕組みです。

### BPF Mapの種類

| Map Type | 用途 | 特徴 |
|----------|------|------|
| **BPF_MAP_TYPE_HASH** | Key-Value Store | 一般的な用途、柔軟 |
| **BPF_MAP_TYPE_ARRAY** | 固定サイズ配列 | 高速、インデックスアクセス |
| **BPF_MAP_TYPE_PERF_EVENT_ARRAY** | イベントストリーム | 高頻度イベント向け |
| **BPF_MAP_TYPE_RINGBUF** | リングバッファ | 低レイテンシ、新しい実装 |
| **BPF_MAP_TYPE_LRU_HASH** | LRUキャッシュ | 自動エビクション |

### 実例: パケットカウンタ

```c
// BPF Map: パケット数を記録
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);    // IP address
    __type(value, u64);  // packet count
} packet_count SEC(".maps");

SEC("socket")
int count_packets(struct __sk_buff *skb) {
    // 送信元IPアドレスを取得
    u32 src_ip = ... // IPヘッダーから取得

    // 現在のカウントを取得
    u64 *count = bpf_map_lookup_elem(&packet_count, &src_ip);

    if (count) {
        // 既存エントリをインクリメント
        __sync_fetch_and_add(count, 1);
    } else {
        // 新規エントリを作成
        u64 initial = 1;
        bpf_map_update_elem(&packet_count, &src_ip, &initial, BPF_NOEXIST);
    }

    return 0;
}
```

**User Space側でのMap読み取り**:
```c
// User Spaceプログラム（C言語）
#include <bpf/libbpf.h>

int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/packet_count");

    u32 key = 0;
    u32 next_key;
    u64 value;

    // 全エントリを列挙
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        bpf_map_lookup_elem(map_fd, &next_key, &value);

        // IPアドレスとパケット数を表示
        printf("IP: %u.%u.%u.%u, Packets: %llu\n",
               (next_key >> 24) & 0xFF,
               (next_key >> 16) & 0xFF,
               (next_key >> 8) & 0xFF,
               next_key & 0xFF,
               value);

        key = next_key;
    }

    return 0;
}
```

## パフォーマンスチューニング

StratoSharkのパフォーマンスを最適化する方法を紹介します。

### 1. バッファサイズの調整

```bash
# デフォルト（4MB）
stratoshark capture --interface eth0

# 大規模環境向け（256MB）
stratoshark capture \
  --interface eth0 \
  --buffer-size 256MB

# 低メモリ環境（1MB）
stratoshark capture \
  --interface eth0 \
  --buffer-size 1MB
```

**推奨設定**:
| 環境 | バッファサイズ | 説明 |
|------|---------------|------|
| 小規模（~10 Pods） | 4MB | デフォルト |
| 中規模（~100 Pods） | 64MB | 推奨 |
| 大規模（1000+ Pods） | 256MB | 高トラフィック対応 |

### 2. フィルタリング戦略

**効率的なフィルタ**:
```bash
# ❌ 非効率: User Spaceでフィルタ
stratoshark capture --interface eth0 | grep "port 80"

# ✅ 効率的: カーネル空間でフィルタ
stratoshark capture --interface eth0 --filter "tcp port 80"

# ✅ さらに効率的: 複合条件
stratoshark capture \
  --interface eth0 \
  --filter "tcp port 80 and host 192.168.1.1"
```

### 3. Ring Buffer vs Perf Events

```
┌──────────────────────────────────────┐
│  Perf Events (従来)                  │
└──────────────────────────────────────┘
- CPU毎にバッファ
- 高頻度イベントに適す
- メモリ使用量が多い

┌──────────────────────────────────────┐
│  Ring Buffer (推奨)                  │
└──────────────────────────────────────┘
- 共有バッファ
- 低レイテンシ
- メモリ効率的
```

**使い分け**:
```bash
# 高頻度イベント（1秒に1000+イベント）
stratoshark capture --event-mode perf

# 通常のキャプチャ（推奨）
stratoshark capture --event-mode ringbuf
```

### 4. CPU Affinity

```bash
# 特定のCPUコアで実行
stratoshark capture \
  --interface eth0 \
  --cpu-affinity 0,1,2,3

# NUMAノードを指定
stratoshark capture \
  --interface eth0 \
  --numa-node 0
```

## トラブルシューティングガイド

StratoShark使用時によくある問題と解決策です。

### 問題1: "Operation not permitted"

**エラー**:
```
Error: Failed to load eBPF program: Operation not permitted
```

**原因**:
- CAP_BPF capabilityがない
- またはrootユーザーでない

**解決策**:
```bash
# 方法1: capabilityを付与
sudo setcap 'cap_bpf,cap_net_admin+ep' /usr/bin/stratoshark

# 方法2: sudoで実行
sudo stratoshark capture --interface eth0

# 方法3: unprivileged BPFを有効化（非推奨）
sudo sysctl kernel.unprivileged_bpf_disabled=0
```

### 問題2: カーネルバージョンが古い

**エラー**:
```
Error: Kernel version 4.14 is too old. Minimum required: 4.15
```

**確認**:
```bash
uname -r
# 4.14.0-generic

# 必要な機能の確認
grep CONFIG_BPF /boot/config-$(uname -r)
```

**解決策**:
1. カーネルをアップグレード（Ubuntu 20.04+ 推奨）
2. または、BPF CO-REなしモードで実行（機能制限あり）

### 問題3: パケットドロップが発生

**症状**:
```
Captured: 10000 packets
Dropped: 500 packets (5%)
```

**原因**:
- バッファサイズ不足
- CPU負荷が高い

**解決策**:
```bash
# バッファサイズを増やす
stratoshark capture \
  --interface eth0 \
  --buffer-size 128MB

# フィルタを厳しくする
stratoshark capture \
  --interface eth0 \
  --filter "tcp port 80" \
  --buffer-size 64MB
```

### 問題4: "BPF program too complex"

**エラー**:
```
Error: BPF verifier rejected program: too complex
```

**原因**:
- eBPFプログラムの命令数が多すぎる
- ループ回数が多すぎる

**解決策**:
```bash
# シンプルなフィルタを使用
stratoshark capture --filter "tcp"

# 複雑なフィルタは避ける
# ❌ 複雑すぎる
--filter "tcp and (port 80 or port 443) and host 192.168.1.1 and ..."

# ✅ シンプルに
--filter "tcp port 80"
```

## まとめ

StratoSharkは、**eBPFの力を活用した新世代のネットワーク解析ツール**です。

**本章のポイント**:
- eBPFによりカーネル空間で安全かつ高速に動作
- BPF Mapsでカーネルとユーザー空間が効率的にデータ交換
- イベントドリブンアーキテクチャで低オーバーヘッド
- Kubernetes/クラウドネイティブ環境に最適化
- パフォーマンスチューニングでさらに高速化可能

**実装レベルの理解**:
- eBPFプログラムの実例を見ることで、内部動作を理解
- BPF Mapsの種類と用途を把握
- パフォーマンスチューニングの手法を習得
- トラブルシューティングの知識を獲得

次章では、実際にStratoSharkをインストールして動かしてみましょう。

## 参考リソース

### eBPF学習リソース
- [eBPF Documentation](https://ebpf.io/what-is-ebpf/)
- [BCC - BPF Compiler Collection](https://github.com/iovisor/bcc)
- [Linux eBPF Features by Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- [Cilium eBPF Guide](https://docs.cilium.io/en/stable/bpf/)

### eBPFプログラミング
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [eBPF Summit Talks](https://ebpf.io/summit-2024/)
- [Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)

### 関連ツール
- [bpftool - BPF introspection tool](https://github.com/libbpf/bpftool)
- [bpftrace - High-level tracing language](https://github.com/iovisor/bpftrace)
- [Falco実践シリーズ](https://zenn.dev/books/falco-practice-series) - eBPFによるランタイムセキュリティ
