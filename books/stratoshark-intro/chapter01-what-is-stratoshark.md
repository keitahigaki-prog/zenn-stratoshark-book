---
title: "StratoSharkとは？ ― 新世代のパケット／イベント解析ツール"
---

# StratoSharkとは？

## 3分でわかる StratoShark

StratoSharkは、**Wiresharkの作者Gerald Combs氏が中心となって開発している次世代のパケット/イベント解析ツール**です。従来のWiresharkが持つ強力な解析機能を継承しつつ、クラウドネイティブ時代に対応した新しいアーキテクチャを採用しています。

### 主な特徴

- ✅ **eBPFベースのキャプチャ** - カーネル空間で効率的にデータを収集
- ✅ **クラウドネイティブ対応** - Kubernetes環境でもシームレスに動作
- ✅ **root権限不要** - 適切な権限設定で一般ユーザーでも実行可能
- ✅ **並列解析** - 大量のデータを高速に処理
- ✅ **CLI & GUI** - コマンドラインでもGUIでも利用可能

:::message
**対象読者**
- SREエンジニア
- ネットワークエンジニア
- セキュリティエンジニア
- Kubernetes管理者
- パフォーマンスチューニング担当者
:::

## なぜStratoSharkが生まれたのか？

### クラウド時代のネットワーク解析の課題

従来のパケットキャプチャツール（tcpdump、Wireshark）は、**物理サーバーや仮想マシンの時代に設計されたツール**です。しかし、コンテナやKubernetesが主流となった現代では、以下のような課題が顕在化しています。

| 課題 | 詳細 |
|------|------|
| **複雑なネットワークトポロジー** | Pod間通信、Service Mesh、CNIプラグインなど、ネットワーク層が複雑化 |
| **短命なコンテナ** | 問題発生時には既にPodが消えていることも |
| **マルチテナント環境** | 特定のNamespace/Podだけをキャプチャしたい |
| **権限管理** | 本番環境でroot権限を付与するのはセキュリティリスク |
| **大量のトラフィック** | マイクロサービス間の通信量は膨大 |

### eBPFという解決策

**eBPF（extended Berkeley Packet Filter）** は、Linuxカーネル内で安全にプログラムを実行できる仕組みです。StratoSharkはeBPFを活用することで、以下を実現しています。

```
┌─────────────────────────────────────────┐
│         User Space                      │
│                                         │
│  ┌──────────────┐    ┌──────────────┐  │
│  │ StratoShark  │    │  GUI/CLI     │  │
│  │   Engine     │←───│              │  │
│  └──────┬───────┘    └──────────────┘  │
└─────────┼──────────────────────────────┘
          │ eBPF Events
┌─────────┼──────────────────────────────┐
│         ↓        Kernel Space          │
│  ┌──────────────┐                      │
│  │ eBPF Program │                      │
│  │  (Probe)     │                      │
│  └──────┬───────┘                      │
│         ↓                              │
│  ┌──────────────┐                      │
│  │ Network Stack│                      │
│  └──────────────┘                      │
└─────────────────────────────────────────┘
```

## Wireshark vs StratoShark

StratoSharkは、**Wiresharkの後継ではなく、補完的な存在**として位置づけられています。

| 観点 | Wireshark | StratoShark |
|------|-----------|-------------|
| **キャプチャ方式** | libpcap/WinPcap | eBPF（Linux） |
| **主な用途** | 詳細なパケット解析 | イベントドリブン解析 |
| **対象環境** | 物理/仮想マシン | クラウドネイティブ |
| **権限** | root/管理者必須 | 適切な設定で一般ユーザー可 |
| **プラットフォーム** | Windows/macOS/Linux | 主にLinux（eBPF依存） |

:::message alert
**StratoSharkはWiresharkを置き換えるものではありません**

両ツールは異なる目的で設計されており、状況に応じて使い分けることが推奨されます。
- **詳細なプロトコル解析** → Wireshark
- **クラウド環境でのトラブルシュート** → StratoShark
:::

## StratoSharkのアーキテクチャ概要

StratoSharkは、以下の3つの主要コンポーネントで構成されています。

### 1. Capture Engine（キャプチャエンジン）

eBPFプログラムを通じてカーネルレベルでイベントを捕捉します。

- ネットワークパケット
- システムコール
- ファイルディスクリプタの操作
- TCP/UDPソケットの状態変化

### 2. Analysis Engine（解析エンジン）

キャプチャしたデータを解析し、構造化します。

- プロトコル解析（HTTP、DNS、TLS等）
- タイムスタンプの正規化
- パケット再構成
- 統計情報の生成

### 3. Visualization（可視化）

CLI/GUIで解析結果を表示します。

- Wireshark風のGUI
- コマンドライン出力
- フィルタリング機能
- カスタムビュー

## 実際の利用シーン

### シーン1: Kubernetes Podの通信デバッグ

```bash
# 特定のPodのHTTP通信をキャプチャ
stratoshark capture --pod my-app-pod-xyz --filter "http"
```

### シーン2: DNS障害の原因調査

```bash
# DNS問い合わせの失敗をトレース
stratoshark capture --filter "dns" --dns-errors-only
```

### シーン3: パフォーマンス問題の特定

```bash
# TCP handshakeの遅延を解析
stratoshark capture --filter "tcp.flags.syn==1" --latency
```

## まとめ

StratoSharkは、**eBPFの力を活用してクラウドネイティブ時代のネットワーク解析を実現するツール**です。Wiresharkの強力な解析機能を継承しながら、Kubernetesやコンテナ環境での使いやすさを追求しています。

次章では、Wiresharkとの具体的な違いと、なぜStratoSharkが必要とされているのかをさらに深掘りしていきます。

## 参考リソース

- [StratoShark公式サイト](https://www.stratoshark.org/)
- [eBPF入門](https://ebpf.io/)
- [Wireshark公式サイト](https://www.wireshark.org/)
