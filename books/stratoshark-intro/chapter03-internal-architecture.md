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

## まとめ

StratoSharkは、**eBPFの力を活用した新世代のネットワーク解析ツール**です。

**重要なポイント**
- eBPFによりカーネル空間で安全かつ高速に動作
- イベントドリブンアーキテクチャで低オーバーヘッド
- Kubernetes/クラウドネイティブ環境に最適化
- OpenTelemetryなど、可観測性エコシステムと統合可能

次章では、実際にStratoSharkをインストールして動かしてみましょう。

## 参考リソース

- [eBPF Documentation](https://ebpf.io/what-is-ebpf/)
- [Linux eBPF Features by Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
