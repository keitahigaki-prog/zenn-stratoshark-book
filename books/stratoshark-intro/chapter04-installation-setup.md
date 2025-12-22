---
title: "インストールとセットアップ ― 環境別の構築手順"
---

# インストールとセットアップ

## 本章の目的

StratoSharkを実際に動作させるための環境構築手順を学びます。Linux、macOS、Kubernetes環境それぞれでの導入方法と、基本的な動作確認までを解説します。

## 前提条件

### 必須要件

StratoSharkを実行するには、以下の要件を満たす必要があります：

| 項目 | 要件 |
|------|------|
| **OS** | Linux 5.8+ (eBPF CO-RE対応), macOS 12+ |
| **カーネル** | BTF対応カーネル（詳細は後述） |
| **権限** | root権限またはCAP_BPF capability |
| **メモリ** | 最低2GB（推奨4GB以上） |
| **CPU** | x86_64, ARM64 (aarch64) |

### カーネル要件の確認

**Linux環境**:

```bash
# カーネルバージョンを確認
uname -r
# 例: 5.15.0-91-generic

# BTF（BPF Type Format）が有効か確認
ls -la /sys/kernel/btf/vmlinux
# 存在すればBTF対応カーネル
```

**BTFが無効の場合**:
- Ubuntu 20.04+: デフォルトで有効
- CentOS/RHEL 8+: デフォルトで有効
- Amazon Linux 2023: デフォルトで有効
- それ以外: カーネルを5.8+にアップグレード

---

## Linux環境でのインストール

### 方法1: パッケージマネージャー（推奨）

#### Ubuntu/Debian

```bash
# Sysdigリポジトリを追加
curl -s https://download.sysdig.com/stable/deb/draios-pubkey.asc | apt-key add -
echo "deb https://download.sysdig.com/stable/deb stable-$(lsb_release -cs)/" | \
  sudo tee /etc/apt/sources.list.d/draios.list

# インストール
sudo apt-get update
sudo apt-get install stratoshark

# バージョン確認
stratoshark --version
```

#### CentOS/RHEL/Amazon Linux

```bash
# Sysdigリポジトリを追加
sudo rpm --import https://download.sysdig.com/DRAIOS-GPG-KEY.public
sudo curl -s -o /etc/yum.repos.d/draios.repo \
  https://download.sysdig.com/stable/rpm/draios.repo

# インストール
sudo yum install stratoshark

# または dnf の場合
sudo dnf install stratoshark

# バージョン確認
stratoshark --version
```

### 方法2: バイナリダウンロード

```bash
# 最新版をダウンロード（例: v0.10.0）
VERSION="0.10.0"
wget https://github.com/stratoshark/stratoshark/releases/download/v${VERSION}/stratoshark-linux-amd64.tar.gz

# 解凍
tar -xzf stratoshark-linux-amd64.tar.gz

# /usr/local/bin に配置
sudo mv stratoshark /usr/local/bin/
sudo chmod +x /usr/local/bin/stratoshark

# 動作確認
stratoshark --version
```

### 方法3: ソースからビルド（開発者向け）

```bash
# 依存パッケージのインストール
sudo apt-get install git cmake build-essential \
  libelf-dev zlib1g-dev libbpf-dev

# リポジトリをクローン
git clone https://github.com/stratoshark/stratoshark.git
cd stratoshark

# ビルド
mkdir build && cd build
cmake ..
make -j$(nproc)

# インストール
sudo make install
```

---

## macOS環境でのインストール

### Homebrewを使用（推奨）

```bash
# Homebrewがインストールされていない場合
# /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# StratoSharkをインストール
brew tap stratoshark/tap
brew install stratoshark

# バージョン確認
stratoshark --version
```

### 制限事項（macOS）

macOSではeBPFが利用できないため、以下の制限があります：

| 機能 | macOS | Linux |
|------|-------|-------|
| **ネットワークキャプチャ** | ✅ (libpcap使用) | ✅ |
| **eBPFプログラム実行** | ❌ | ✅ |
| **システムコール監視** | ❌ | ✅ |
| **カーネルイベント** | ❌ | ✅ |

**macOSでの推奨用途**:
- pcapファイルの解析
- リモートキャプチャの閲覧
- Kubernetesクラスタからのキャプチャ取得

---

## Kubernetes環境での導入

### DaemonSetとしてデプロイ

StratoSharkをKubernetesクラスタ全体に展開する方法です。

#### 1. Namespace作成

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: stratoshark
```

```bash
kubectl apply -f namespace.yaml
```

#### 2. ServiceAccount作成

```yaml
# serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: stratoshark
  namespace: stratoshark
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: stratoshark
rules:
- apiGroups: [""]
  resources: ["pods", "nodes"]
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
  namespace: stratoshark
```

```bash
kubectl apply -f serviceaccount.yaml
```

#### 3. DaemonSet作成

```yaml
# daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: stratoshark
  namespace: stratoshark
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
      containers:
      - name: stratoshark
        image: sysdig/stratoshark:latest
        securityContext:
          privileged: true  # eBPFプログラムのロードに必要
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
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
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
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
      tolerations:
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
```

```bash
kubectl apply -f daemonset.yaml
```

#### 4. デプロイ確認

```bash
# Pod一覧を確認
kubectl get pods -n stratoshark -o wide

# 特定ノードのPodログを確認
kubectl logs -n stratoshark stratoshark-xxxxx

# Podにアクセスしてキャプチャ実行
kubectl exec -it -n stratoshark stratoshark-xxxxx -- stratoshark capture
```

### Helmチャートでデプロイ（推奨）

```bash
# Helmリポジトリを追加
helm repo add stratoshark https://stratoshark.github.io/charts
helm repo update

# インストール
helm install stratoshark stratoshark/stratoshark \
  --namespace stratoshark \
  --create-namespace \
  --set agent.ebpf.enabled=true

# ステータス確認
helm status stratoshark -n stratoshark
```

---

## 動作確認

### 基本的な動作テスト

#### 1. ヘルプメニューの表示

```bash
stratoshark --help
```

**期待される出力**:
```
StratoShark 0.10.0 - Network and Event Analysis Tool

Usage: stratoshark [OPTIONS] <COMMAND>

Commands:
  capture  Start packet capture
  analyze  Analyze pcap file
  live     Live capture and display
  help     Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose  Increase verbosity
  -h, --help     Print help
  -V, --version  Print version
```

#### 2. 簡単なキャプチャテスト

```bash
# 5秒間のキャプチャ（rootまたはsudo必要）
sudo stratoshark capture --duration 5s --output test.pcap

# キャプチャファイルの確認
ls -lh test.pcap

# ファイル内容の確認
stratoshark analyze test.pcap --summary
```

**期待される出力**:
```
Capture Summary:
  Duration: 5.02s
  Packets: 1,234
  Bytes: 1.2 MB
  Protocols: TCP (67%), UDP (28%), ICMP (5%)
```

#### 3. eBPFプログラムの動作確認

```bash
# eBPFプログラムがロードされているか確認
sudo bpftool prog list | grep stratoshark

# 例の出力:
# 42: tracing  name stratoshark_tc  tag 2e7a7c6f8b3d9e1a
# 43: kprobe   name tcp_sendmsg    tag 7f8e9d0c1a2b3c4d
```

---

## トラブルシューティング

### 問題1: 権限エラー

**エラー**:
```
Error: Permission denied (you must be root)
```

**解決策**:
```bash
# 方法1: sudoを使用
sudo stratoshark capture

# 方法2: CAP_BPF capabilityを付与（Linux 5.8+）
sudo setcap cap_bpf,cap_net_admin=eip $(which stratoshark)
stratoshark capture
```

### 問題2: BTFが見つからない

**エラー**:
```
Error: BTF not found in /sys/kernel/btf/vmlinux
```

**解決策**:
```bash
# カーネルバージョンを確認
uname -r

# BTF対応カーネルにアップグレード
# Ubuntu
sudo apt-get upgrade linux-generic

# または、BTF情報をダウンロード（一部ディストリビューション）
sudo apt-get install linux-headers-$(uname -r)
```

### 問題3: Kubernetes Podが起動しない

**症状**:
```bash
kubectl get pods -n stratoshark
# STATUS: CrashLoopBackOff
```

**デバッグ手順**:
```bash
# ログを確認
kubectl logs -n stratoshark stratoshark-xxxxx

# よくあるエラー1: Privileged権限がない
# → securityContext.privileged: true を確認

# よくあるエラー2: ノードのカーネルが古い
kubectl describe node <node-name> | grep "Kernel Version"
# → 5.8以上であることを確認

# よくあるエラー3: ホストパスがマウントできない
# → volumeMountsとvolumesの設定を確認
```

### 問題4: macOSでeBPF機能が使えない

**これは正常な動作です**。macOSではeBPFが利用できないため、以下のワークアラウンドを使用してください：

```bash
# ワークアラウンド1: pcapファイルの解析に使用
stratoshark analyze capture.pcap

# ワークアラウンド2: リモートLinuxマシンでキャプチャ
ssh linux-host "sudo stratoshark capture --output - | gzip" | \
  gunzip | stratoshark analyze -

# ワークアラウンド3: Kubernetesクラスタから取得
kubectl exec -n stratoshark stratoshark-xxxxx -- \
  stratoshark capture --output - | stratoshark analyze -
```

---

## 設定ファイル

### デフォルト設定

StratoSharkは、以下の場所で設定ファイルを読み込みます：

```bash
# システム全体の設定
/etc/stratoshark/config.yaml

# ユーザー固有の設定
~/.config/stratoshark/config.yaml
```

### 設定例

```yaml
# ~/.config/stratoshark/config.yaml
capture:
  default_interface: eth0
  buffer_size: 16MB
  snaplen: 65535

filters:
  enabled: true
  default: "tcp port 80 or tcp port 443"

output:
  format: pcap
  compress: true
  directory: ~/captures

ebpf:
  enabled: true
  programs:
    - tcp_monitor
    - http_parser

logging:
  level: info
  output: /var/log/stratoshark.log
```

---

## 次のステップ

StratoSharkのインストールが完了しました！次章では、CLIでのキャプチャ操作を学びます。

**次章で学ぶこと**:
- `stratoshark capture` コマンドの詳細
- フィルタリングとスナップショット
- 出力形式とストレージ管理
- リアルタイム解析の基本

---

## まとめ

本章では、StratoSharkの環境構築方法を学びました：

✅ **Linux環境**: パッケージマネージャーまたはバイナリでインストール
✅ **macOS環境**: Homebrewでインストール（eBPF機能は制限付き）
✅ **Kubernetes環境**: DaemonSetまたはHelmでデプロイ
✅ **動作確認**: 基本的なキャプチャとeBPFプログラムの確認
✅ **トラブルシューティング**: よくある問題と解決策

次章では、実際にStratoSharkを使ったキャプチャ操作を深掘りします。
