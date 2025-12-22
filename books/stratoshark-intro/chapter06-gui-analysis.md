---
title: "GUIでの解析 ― Wiresharkライクなビジュアル分析"
---

# GUIでの解析

## 本章の目的

StratoSharkのGUI（グラフィカルユーザーインターフェース）を使った実践的なパケット解析手法を学びます。Wireshark経験者にとって馴染み深いインターフェースで、eBPFによる拡張機能を活用した高度な分析を解説します。

## GUIの起動

### 基本的な起動方法

```bash
# GUIモードで起動
stratoshark

# または特定のpcapファイルを開く
stratoshark capture.pcap

# リモートキャプチャを開く
stratoshark ssh://user@host/tmp/capture.pcap
```

**起動時の画面構成**:
```
┌─────────────────────────────────────────────────────┐
│  File  Edit  View  Go  Capture  Analyze  Statistics │
├─────────────────────────────────────────────────────┤
│  [Filter: tcp.port == 443          ] [Apply] [Clear]│
├───────────────┬─────────────────────────────────────┤
│               │  Packet List (パケット一覧)          │
│  Packet       │  ┌────┬──────┬────────┬──────┬────┐│
│  Details      │  │No  │Time  │Source  │Dest  │Info││
│  (階層表示)    │  ├────┼──────┼────────┼──────┼────┤│
│               │  │1   │0.000 │10.0.1.2│10... │... ││
│               │  └────┴──────┴────────┴──────┴────┘│
├───────────────┼─────────────────────────────────────┤
│  Packet       │  Packet Details (詳細パネル)         │
│  Bytes        │  ▼ Frame 1: 74 bytes on wire        │
│  (16進数表示) │  ▼ Ethernet II                       │
│               │  ▼ Internet Protocol Version 4       │
└───────────────┴─────────────────────────────────────┘
```

---

## メイン画面の構成

### 1. パケットリストペイン（上部）

パケットの一覧表示エリアです。

**表示される主な情報**:
| 列 | 内容 |
|----|------|
| **No.** | パケット番号 |
| **Time** | キャプチャ開始からの相対時刻 |
| **Source** | 送信元IPアドレス |
| **Destination** | 宛先IPアドレス |
| **Protocol** | プロトコル（TCP/UDP/ICMP等） |
| **Length** | パケット長 |
| **Info** | パケット情報（概要） |

**色分け（カラーリングルール）**:
- 🟢 **緑**: HTTPトラフィック
- 🔵 **青**: DNSトラフィック
- ⚫ **黒**: TCPトラフィック（正常）
- 🔴 **赤**: TCPエラー（再送信、RST等）
- 🟡 **黄**: TCPの問題（重複ACK等）

### 2. パケット詳細ペイン（中央）

選択したパケットの階層構造を表示します。

**階層構造の例**:
```
▼ Frame 42: 1514 bytes on wire
  ├─ Arrival Time: 2025-01-10 10:15:32.123456000 JST
  └─ Frame Length: 1514 bytes
▼ Ethernet II, Src: 00:1a:2b:3c:4d:5e, Dst: 00:6f:7e:8d:9c:0a
  ├─ Destination: 00:6f:7e:8d:9c:0a
  ├─ Source: 00:1a:2b:3c:4d:5e
  └─ Type: IPv4 (0x0800)
▼ Internet Protocol Version 4, Src: 192.168.1.100, Dst: 172.217.175.46
  ├─ Version: 4
  ├─ Header Length: 20 bytes
  ├─ Total Length: 1500
  ├─ Source Address: 192.168.1.100
  └─ Destination Address: 172.217.175.46
▼ Transmission Control Protocol, Src Port: 54321, Dst Port: 443
  ├─ Source Port: 54321
  ├─ Destination Port: 443 (HTTPS)
  ├─ Sequence Number: 12345
  ├─ Acknowledgment Number: 67890
  ├─ Flags: 0x018 (PSH, ACK)
  └─ Window: 65535
▼ Transport Layer Security
  ├─ TLS Record Layer: Application Data
  └─ Encrypted Application Data
```

### 3. バイトペイン（下部）

パケットの生データを16進数とASCII表示します。

**表示例**:
```
0000  00 6f 7e 8d 9c 0a 00 1a 2b 3c 4d 5e 08 00 45 00   .o~.....+<M^..E.
0010  05 dc 1a 2b 40 00 40 06 3c 4d c0 a8 01 64 ac d9   ...+@.@.<M...d..
0020  af 2e d4 31 01 bb 00 00 30 39 00 01 09 32 80 18   ...1....09...2..
0030  ff ff 7c 3d 00 00 01 01 08 0a 12 34 56 78 87 65   ..|=.......4Vx.e
```

---

## ディスプレイフィルタ

### 基本的なフィルタ構文

Wiresharkと互換性のあるディスプレイフィルタを使用できます。

#### プロトコル指定

```
# HTTPトラフィックのみ表示
http

# TLS/SSL通信のみ表示
tls

# DNSクエリのみ表示
dns

# ICMPパケットのみ表示
icmp
```

#### IPアドレスフィルタ

```
# 特定の送信元IP
ip.src == 192.168.1.100

# 特定の宛先IP
ip.dst == 8.8.8.8

# 特定のIP（送信元または宛先）
ip.addr == 192.168.1.100

# サブネット指定
ip.addr == 192.168.1.0/24
```

#### ポート指定

```
# HTTPSトラフィック
tcp.port == 443

# 複数ポート
tcp.port in {80 443 8080}

# 送信元ポート指定
tcp.srcport == 54321

# 宛先ポート指定
tcp.dstport == 443
```

#### 論理演算子

```
# AND条件
ip.src == 192.168.1.100 && tcp.port == 443

# OR条件
tcp.port == 80 || tcp.port == 443

# NOT条件
!arp

# 複合条件
(ip.addr == 192.168.1.100) && (tcp.port == 443 || tcp.port == 80)
```

### 高度なフィルタ

#### TCP分析フィルタ

```
# TCP再送信パケット
tcp.analysis.retransmission

# TCP重複ACK
tcp.analysis.duplicate_ack

# TCPゼロウィンドウ（受信バッファ満杯）
tcp.analysis.zero_window

# TCP接続確立（3-way handshake）
tcp.flags.syn == 1 && tcp.flags.ack == 0

# TCP接続終了（FIN）
tcp.flags.fin == 1

# TCP接続リセット（RST）
tcp.flags.reset == 1
```

#### HTTP分析フィルタ

```
# HTTPリクエストメソッド
http.request.method == "GET"
http.request.method == "POST"

# HTTPステータスコード
http.response.code == 200
http.response.code >= 400  # エラーレスポンス

# 特定のHTTPヘッダ
http.host == "example.com"
http.user_agent contains "Chrome"

# HTTPコンテンツタイプ
http.content_type contains "json"
```

#### DNS分析フィルタ

```
# DNSクエリのみ
dns.flags.response == 0

# DNSレスポンスのみ
dns.flags.response == 1

# 特定のドメイン名
dns.qry.name == "example.com"

# DNS失敗（NXDOMAIN）
dns.flags.rcode == 3
```

### フィルタのお気に入り登録

よく使うフィルタを保存できます。

**手順**:
1. フィルタバーに条件を入力
2. 右側の「⭐」ボタンをクリック
3. 名前を付けて保存

**例**:
```
名前: HTTPS Traffic
フィルタ: tcp.port == 443

名前: HTTP Errors
フィルタ: http.response.code >= 400

名前: Slow Connections
フィルタ: tcp.time_delta > 1
```

---

## パケット解析ワークフロー

### ワークフロー1: HTTP通信の解析

#### ステップ1: HTTPトラフィックを抽出

```
フィルタ: http
```

#### ステップ2: 特定のHTTPセッションを追跡

1. HTTPリクエストパケットを右クリック
2. **Follow → HTTP Stream** を選択

**結果**:
```
GET /api/users HTTP/1.1
Host: api.example.com
User-Agent: curl/7.68.0
Accept: */*

HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 123

{"users": [{"id": 1, "name": "Alice"}]}
```

#### ステップ3: レスポンスタイムを確認

```
フィルタ: http.time > 1
```

これで1秒以上かかったHTTPリクエストを抽出できます。

### ワークフロー2: TCP接続問題の診断

#### ステップ1: TCP問題を抽出

```
フィルタ: tcp.analysis.flags
```

#### ステップ2: TCPストリームを追跡

1. 問題のあるパケットを右クリック
2. **Follow → TCP Stream** を選択

**色分け**:
- 🔴 **赤**: クライアント → サーバー
- 🔵 **青**: サーバー → クライアント

#### ステップ3: TCPフロー統計を確認

**Statistics → Flow Graph** を選択

**表示例**:
```
Client                Server
  |                      |
  |----SYN-------------->|
  |<---SYN+ACK-----------|
  |----ACK-------------->|
  |----Data------------->|
  |<---ACK---------------|
  |----Data------------->|  ← 再送信（赤色）
  |----Data------------->|  ← 再送信（赤色）
  |<---ACK---------------|
```

### ワークフロー3: TLS/SSL証明書の検証

#### ステップ1: TLSハンドシェイクを抽出

```
フィルタ: tls.handshake.type == 1
```

#### ステップ2: 証明書情報を確認

1. **Server Hello** パケットを選択
2. **Packet Details** で展開:
   ```
   ▼ Transport Layer Security
     ▼ TLSv1.2 Record Layer: Handshake Protocol: Certificate
       ▼ Handshake Protocol: Certificate
         ▼ Certificate: example.com
           - Subject: CN=example.com
           - Issuer: CN=Let's Encrypt Authority X3
           - Valid From: 2025-01-01
           - Valid Until: 2025-04-01
   ```

#### ステップ3: 暗号スイートを確認

```
フィルタ: tls.handshake.ciphersuite
```

---

## 統計機能

### 1. プロトコル階層統計

**Statistics → Protocol Hierarchy**

**表示例**:
```
Protocol                     Packets    Bytes      %
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Frame                        10,234    15.2 MB    100%
├─ Ethernet                  10,234    15.2 MB    100%
  ├─ IPv4                    10,120    15.0 MB    98.8%
  │ ├─ TCP                    6,845    10.5 MB    69.0%
  │ │ ├─ HTTP                 1,234     2.1 MB    20.3%
  │ │ └─ TLS                  3,456     5.8 MB    55.2%
  │ ├─ UDP                    3,275     4.5 MB    29.7%
  │ │ ├─ DNS                    567   0.05 MB     1.7%
  │ │ └─ QUIC                 2,708     4.4 MB    82.8%
  │ └─ ICMP                       0         0      0%
  └─ IPv6                       114     0.2 MB     1.1%
```

### 2. 会話統計（Conversations）

**Statistics → Conversations**

#### TCP会話
```
Address A          Port A   Address B          Port B   Packets  Bytes    Duration
192.168.1.100      54321    172.217.175.46     443      1,234    1.5 MB   45.2s
192.168.1.100      54322    10.0.1.50          8080       567    0.8 MB   12.3s
```

#### UDP会話
```
Address A          Port A   Address B          Port B   Packets  Bytes
192.168.1.100      53124    8.8.8.8            53          12    1.2 KB
192.168.1.100      53125    8.8.4.4            53           8    0.9 KB
```

### 3. エンドポイント統計

**Statistics → Endpoints**

```
Address            Packets   Bytes      Tx Packets  Rx Packets
192.168.1.100      5,678     8.5 MB     2,890       2,788
172.217.175.46     2,345     3.2 MB     1,200       1,145
10.0.1.50          1,123     1.8 MB       560         563
```

### 4. I/Oグラフ

**Statistics → I/O Graph**

時系列でトラフィック量を可視化します。

**グラフの種類**:
- **Packets/sec**: 秒あたりのパケット数
- **Bytes/sec**: 秒あたりのバイト数
- **Bits/sec**: 秒あたりのビット数

**フィルタ別グラフ**:
```
Graph 1 (青): tcp
Graph 2 (赤): udp
Graph 3 (緑): icmp
```

### 5. HTTPリクエスト統計

**Statistics → HTTP → Requests**

```
Request Method    Count    Percent
GET               4,567    78.5%
POST                890    15.3%
PUT                 234     4.0%
DELETE              123     2.1%

Status Code       Count    Percent
200 OK            3,890    84.2%
404 Not Found       456     9.9%
500 Server Error    123     2.7%
```

---

## eBPF拡張機能（StratoShark独自）

StratoSharkは、eBPFによる拡張情報を表示できます。

### 1. プロセス情報の表示

**表示方法**:
- パケット詳細ペインで **eBPF Metadata** セクションを展開

**表示例**:
```
▼ eBPF Metadata
  ├─ Process ID: 12345
  ├─ Process Name: nginx
  ├─ Thread ID: 12346
  ├─ User ID: 1000 (www-data)
  ├─ Container ID: a1b2c3d4e5f6
  ├─ Pod Name: nginx-deployment-7d9c8b5f4-abc12
  └─ Namespace: production
```

**フィルタ例**:
```
# 特定プロセスのトラフィックのみ
ebpf.process.name == "nginx"

# 特定Podのトラフィックのみ
ebpf.k8s.pod == "nginx-deployment-7d9c8b5f4-abc12"

# 特定コンテナのトラフィックのみ
ebpf.container.id contains "a1b2c3d4"
```

### 2. システムコール情報

```
▼ eBPF System Call
  ├─ Syscall: sendto
  ├─ Return Value: 1024 (bytes sent)
  ├─ Latency: 0.125 ms
  └─ CPU: 2
```

**フィルタ例**:
```
# システムコールレイテンシが高いパケット
ebpf.syscall.latency > 0.01

# 特定のシステムコール
ebpf.syscall.name == "sendto"
```

### 3. ファイルディスクリプタ情報

```
▼ eBPF File Descriptor
  ├─ FD Number: 42
  ├─ FD Type: socket
  ├─ Socket Type: TCP
  └─ Local Address: 192.168.1.100:54321
```

---

## エクスポート機能

### 1. パケットのエクスポート

#### 表示中のパケットをエクスポート

**File → Export Specified Packets**

**オプション**:
- **All packets**: すべてのパケット
- **Selected packet**: 選択中のパケットのみ
- **Marked packets**: マークしたパケットのみ
- **Displayed packets**: フィルタ後のパケットのみ

#### フォーマット選択
```
- pcap
- pcapng (推奨: メタデータ保持)
- JSON
- CSV
- XML
```

### 2. HTTPオブジェクトのエクスポート

**File → Export Objects → HTTP**

**用途**:
- キャプチャ内のHTMLファイル
- 画像ファイル（JPEG/PNG/GIF）
- CSSファイル
- JavaScriptファイル

**表示例**:
```
Packet   Hostname          Content Type        Size     Filename
1234     example.com       text/html          12 KB     index.html
1567     cdn.example.com   image/jpeg        245 KB     logo.jpg
2345     api.example.com   application/json    2 KB     users.json
```

### 3. TLS秘密鍵のインポート

**Edit → Preferences → Protocols → TLS**

**設定項目**:
```
(Pre)-Master-Secret log filename: /path/to/sslkeylog.txt
```

これで暗号化されたTLS通信を復号化して表示できます。

**sslkeylog.txt の生成**:
```bash
# Chromeの場合
export SSLKEYLOGFILE=/tmp/sslkeylog.txt
google-chrome

# curlの場合
export SSLKEYLOGFILE=/tmp/sslkeylog.txt
curl https://example.com
```

---

## カスタマイズ

### 1. カラムのカスタマイズ

**表示するカラムを追加**:
1. パケット詳細ペインでフィールドを右クリック
2. **Apply as Column** を選択

**例**:
- TCP Sequence Number
- HTTP Host
- TLS Server Name
- eBPF Process Name

### 2. カラーリングルールのカスタマイズ

**View → Coloring Rules**

**カスタムルール例**:
```
名前: High Latency HTTP
フィルタ: http.time > 1
背景色: 赤
前景色: 白

名前: My Application
フィルタ: ip.addr == 192.168.1.100
背景色: 黄
前景色: 黒
```

### 3. タイムディスプレイフォーマット

**View → Time Display Format**

**オプション**:
- **Date and Time of Day**: 2025-01-10 10:15:32.123456
- **Time of Day**: 10:15:32.123456
- **Seconds Since Beginning of Capture**: 0.000000
- **Seconds Since Previous Displayed Packet**: 0.001234
- **UTC Date and Time of Day**: 2025-01-10 01:15:32.123456 UTC

---

## 実践例

### 例1: レイテンシスパイクの調査

**シナリオ**: APIのレスポンスタイムが突然悪化

**手順**:
1. HTTPフィルタを適用:
   ```
   http
   ```

2. レスポンスタイムでソート:
   - **Time** カラムを右クリック
   - **Sort** を選択

3. 遅いリクエストを特定:
   ```
   フィルタ: http.time > 1
   ```

4. TCPストリームを確認:
   - 該当パケットを右クリック
   - **Follow → TCP Stream**

5. TCP分析:
   ```
   フィルタ: tcp.analysis.flags && ip.addr == <問題のIP>
   ```

**発見できる問題**:
- TCP再送信（`tcp.analysis.retransmission`）
- ゼロウィンドウ（`tcp.analysis.zero_window`）
- 重複ACK（`tcp.analysis.duplicate_ack`）

### 例2: DNS解決失敗の調査

**シナリオ**: アプリケーションが特定のドメインに接続できない

**手順**:
1. DNSクエリを抽出:
   ```
   dns.qry.name == "problem-domain.com"
   ```

2. レスポンスコードを確認:
   ```
   dns.flags.rcode != 0
   ```

3. タイムアウトを確認:
   - クエリとレスポンスの時間差を測定
   - **Statistics → DNS** で統計表示

**発見できる問題**:
- NXDOMAIN（ドメイン不存在）
- SERVFAIL（DNSサーバーエラー）
- タイムアウト（応答なし）

### 例3: TLS/SSL証明書エラーの調査

**シナリオ**: HTTPS接続が失敗する

**手順**:
1. TLSハンドシェイクを抽出:
   ```
   tls.handshake
   ```

2. アラートを確認:
   ```
   tls.alert_message
   ```

3. 証明書チェーンを確認:
   - **Server Hello** パケットを選択
   - **Certificate** セクションを展開

**発見できる問題**:
- 証明書期限切れ
- ホスト名不一致
- 自己署名証明書
- 暗号スイート非対応

### 例4: Kubernetes Podのトラフィック分析

**シナリオ**: 特定PodのネットワークI/Oを調査

**手順（StratoShark独自機能）**:
1. eBPFメタデータでフィルタ:
   ```
   ebpf.k8s.pod == "nginx-deployment-7d9c8b5f4-abc12"
   ```

2. プロセス別に分析:
   ```
   ebpf.process.name == "nginx"
   ```

3. 統計を確認:
   - **Statistics → Conversations**
   - **Statistics → Endpoints**

4. I/Oグラフで可視化:
   - **Statistics → I/O Graph**

---

## パケットマーキングと注釈

### パケットのマーキング

重要なパケットにマークを付けて後で参照できます。

**マーク方法**:
1. パケットを選択
2. **Edit → Mark/Unmark Packet** (Ctrl+M / Cmd+M)
3. マークされたパケットは背景が変わる

**マーク済みパケットの表示**:
```
# マーク済みパケットのみ表示
frame.marked == 1

# マークされていないパケット
frame.marked == 0
```

**一括マーク**:
```
1. フィルタを適用: tcp.analysis.retransmission
2. Edit → Mark All Displayed
3. すべての再送信パケットがマークされる
```

**マークの活用例**:
- 問題のあるパケットを識別
- 特定のトランザクションを追跡
- エクスポート時にマーク済みパケットのみ保存

### パケットへのコメント追加

**コメント追加手順**:
1. パケットを右クリック
2. **Edit Packet Comment** を選択
3. コメントを入力

**コメント例**:
```
"このパケットで接続タイムアウト発生"
"ここから再送信が始まる"
"証明書検証エラー"
```

**コメント付きパケットのフィルタ**:
```
# コメントがあるパケットのみ
frame.comment
```

**コメントの保存**:
- pcapng形式で保存するとコメントも保存される
- pcap形式ではコメントは保存されない

---

## Expert Information System

StratoSharkには、自動でネットワーク問題を検出する **Expert System** が組み込まれています。

### Expert Infoの確認

**Analyze → Expert Information**

**表示される情報レベル**:
| レベル | 色 | 意味 |
|--------|-----|------|
| **Chat** | 青 | 情報提供 |
| **Note** | 水色 | 注意事項 |
| **Warn** | 黄 | 警告 |
| **Error** | 赤 | エラー |

### Expert Infoの例

#### ネットワーク層
```
[Error] Duplicate IP address detected
  → 同じIPアドレスが複数のMACアドレスで使用されている

[Warn] TTL expired in transit
  → パケットのTTLが0になった（ルーティングループ？）

[Note] Fragmented IP packet
  → IPパケットが断片化されている
```

#### トランスポート層
```
[Error] TCP Retransmission
  → TCPパケットが再送信された

[Warn] TCP Window Full
  → 受信ウィンドウが満杯（送信側がデータを送れない）

[Error] TCP Reset
  → TCP接続が強制終了された

[Warn] TCP Out-Of-Order
  → パケットが順序通りに届いていない
```

#### アプリケーション層
```
[Error] HTTP 404 Not Found
  → リソースが見つからない

[Error] TLS Alert: Certificate Expired
  → SSL証明書が期限切れ

[Warn] DNS No Such Name
  → ドメイン名が存在しない（NXDOMAIN）
```

### Expert Infoのフィルタ

```
# すべてのエラーレベルのみ表示
expert.severity == error

# 警告以上（警告+エラー）
expert.severity >= warn

# TCP関連の問題のみ
expert.group == "Sequence"

# 特定のメッセージ
expert.message contains "Retransmission"
```

### Expert Infoの活用

**問題の優先順位付け**:
1. **Error** を最初に調査
2. **Warn** で潜在的な問題を特定
3. **Note/Chat** で補足情報を確認

**典型的なワークフロー**:
```
1. Expert Information を開く
2. Errorタブを確認
3. 該当パケットをダブルクリックして詳細表示
4. Follow TCP Stream で全体を把握
5. 根本原因を特定
```

---

## 名前解決の設定

IPアドレスやMACアドレスを人間が読みやすい名前に変換できます。

### 名前解決の有効化

**Edit → Preferences → Name Resolution**

**オプション**:
```
☑ Resolve MAC addresses
  → MACアドレスをベンダー名に変換

☑ Resolve transport names
  → ポート番号をサービス名に変換（80 → http）

☑ Resolve network (IP) addresses
  → IPアドレスをホスト名に変換（DNSルックアップ）

☑ Use an external network name resolver
  → 外部DNSサーバーを使用

☑ Resolve DNS cache
  → キャプチャ内のDNS応答を使用
```

### 名前解決の例

**解決前**:
```
192.168.1.100 → 8.8.8.8
```

**解決後**:
```
my-laptop.local → dns.google
```

**ポート名解決**:
```
解決前: TCP 443
解決後: TCP https
```

**MACアドレス解決**:
```
解決前: 00:1a:2b:3c:4d:5e
解決後: 00:1a:2b:3c:4d:5e (Apple)
```

### カスタムホストファイル

**Edit → Preferences → Name Resolution → Hosts File**

**形式** (`/etc/hosts` と同じ):
```
# カスタムホスト名
192.168.1.100    my-app-server
192.168.1.101    my-db-server
10.0.1.50        my-api-gateway

# IPv6も対応
2001:db8::1      my-ipv6-server
```

**使用例**:
```
# フィルタでホスト名を使用
ip.host == "my-app-server"

# 表示時にホスト名が表示される
Source: my-app-server (192.168.1.100)
```

---

## プロファイル管理

異なるシナリオ用に複数の設定プロファイルを管理できます。

### プロファイルの作成

**Edit → Configuration Profiles**

**デフォルトプロファイル**:
- **Default**: 標準設定
- **Bluetooth**: Bluetooth解析用
- **Classic**: Wireshark Classic風

### カスタムプロファイルの作成

**手順**:
1. **Edit → Configuration Profiles → New**
2. プロファイル名を入力（例: "Production Monitoring"）
3. 設定をカスタマイズ

**プロファイルごとの設定**:
- ディスプレイフィルタのブックマーク
- カラーリングルール
- カラムレイアウト
- 名前解決設定
- プロトコル優先度

### プロファイル例

#### プロファイル: "HTTP Debug"
```
設定:
- カラーリング: HTTPエラーを赤で強調
- カラム追加: HTTP Status Code, Response Time
- フィルタブックマーク:
  - "HTTP Errors": http.response.code >= 400
  - "Slow Requests": http.time > 1
```

#### プロファイル: "Kubernetes"
```
設定:
- カラム追加: eBPF Pod Name, eBPF Namespace
- カラーリング: 本番Podを黄色で強調
- フィルタブックマーク:
  - "Production Pods": ebpf.k8s.namespace == "production"
  - "Error Pods": ebpf.k8s.pod contains "error"
```

#### プロファイル: "Security Analysis"
```
設定:
- カラーリング: 不審なポートを赤で強調
- フィルタブックマーク:
  - "Port Scanning": tcp.flags.syn == 1 && tcp.flags.ack == 0
  - "Failed Connections": tcp.flags.reset == 1
- Expert Info: Error/Warn のみ表示
```

### プロファイルの切り替え

**方法1: メニューから**
```
Edit → Configuration Profiles → <プロファイル名>
```

**方法2: 右下のステータスバー**
```
右下の "Profile: Default" をクリック → プロファイル選択
```

---

## 高度な統計機能

### TCP Stream Analysis

**Statistics → TCP Stream Graphs**

#### 1. Round Trip Time (RTT) Graph

**表示方法**: **Statistics → TCP Stream Graphs → Round Trip Time Graph**

**用途**:
- ネットワークレイテンシの推移を確認
- RTTスパイクの検出

**グラフの見方**:
```
RTT (ms)
  │
  │    ╱╲
  │   ╱  ╲      ← レイテンシスパイク（問題）
  │  ╱    ╲
  │─────────────
  └──────────────→ Time
```

**正常なパターン**:
- RTTが一定（±10ms程度）
- 急激な上昇がない

**問題のあるパターン**:
- RTTが急激に上昇（ネットワーク遅延）
- RTTが徐々に増加（輻輳）
- RTTが不安定（ジッター）

#### 2. Throughput Graph

**表示方法**: **Statistics → TCP Stream Graphs → Throughput Graph**

**用途**:
- スループットの推移を確認
- 帯域制限の検出

**グラフの見方**:
```
Throughput (Mbps)
  │
  │─────────      ← 帯域制限（頭打ち）
  │╱
  │
  └──────────────→ Time
```

**分析ポイント**:
- 期待値に達しているか
- 頭打ちになっていないか（帯域制限）
- スループットが安定しているか

#### 3. Window Scaling Graph

**表示方法**: **Statistics → TCP Stream Graphs → Window Scaling Graph**

**用途**:
- TCP受信ウィンドウのサイズ推移
- フロー制御の確認

**グラフの見方**:
```
Window Size (bytes)
  │
  │─────────      ← 常に満杯（送信側が待機）
  │
  │      ╲
  │       ╲╲╲    ← ゼロウィンドウ（受信側が処理不可）
  └──────────────→ Time
```

**問題パターン**:
- ウィンドウが0になる（受信側の処理が追いつかない）
- ウィンドウが常に小さい（受信バッファ不足）

### Flow Graph（シーケンス図）

**Statistics → Flow Graph**

**表示内容**:
- パケットの送受信をシーケンス図で表示
- TCP 3-way handshake、データ転送、切断を可視化

**表示例**:
```
Client (192.168.1.100)              Server (10.0.1.50)
      │                                    │
      │─────[SYN]─────────────────────────>│  1. 接続要求
      │                                    │
      │<────[SYN, ACK]─────────────────────│  2. 接続受諾
      │                                    │
      │─────[ACK]─────────────────────────>│  3. 接続確立
      │                                    │
      │─────[PSH, ACK] HTTP GET───────────>│  4. データ送信
      │                                    │
      │<────[ACK]─────────────────────────-│  5. ACK受信
      │                                    │
      │<────[PSH, ACK] HTTP 200───────────-│  6. レスポンス
      │                                    │
      │─────[ACK]─────────────────────────>│  7. ACK送信
      │                                    │
      │─────[FIN, ACK]────────────────────>│  8. 切断要求
      │                                    │
      │<────[FIN, ACK]────────────────────-│  9. 切断確認
      │                                    │
      │─────[ACK]─────────────────────────>│  10. 完了
```

**活用方法**:
- 接続確立の問題を特定（SYN再送信）
- データ転送の順序を確認
- 切断処理の異常を検出

### Service Response Time

**Statistics → Service Response Time**

**対応プロトコル**:
- HTTP
- DNS
- SMB
- NFS
- RPC

**HTTP例**:
```
HTTP Request-Response Statistics

Method    Count    Min (ms)  Max (ms)  Avg (ms)  StdDev
GET       1,234    5.2       1,234.5   45.6      123.4
POST      567      12.3      567.8     89.1      234.5
PUT       123      8.9       234.5     56.7      89.0
DELETE    45       3.4       123.4     34.5      45.6

Status Code   Count    Percent
200 OK        1,890    95.2%
404 Not Found 78       3.9%
500 Error     18       0.9%
```

**分析ポイント**:
- 平均レスポンスタイム
- 最大レスポンスタイム（異常値）
- 標準偏差（ばらつき）

### Packet Lengths

**Statistics → Packet Lengths**

**表示内容**:
- パケットサイズの分布
- MTUの確認
- フラグメンテーションの検出

**グラフ例**:
```
Packet Size Distribution

Count
  │
  │ ████
  │ ████        ← 多くは64バイト（ACKパケット）
  │ ████
  │ ████ ██     ← 1514バイト（MTU）
  │ ████ ██
  └──────────────→ Size (bytes)
     64  1514
```

**分析ポイント**:
- 小さいパケットが多い → ACK/制御パケット
- 1514バイト付近が多い → データ転送（Ethernet MTU）
- 1514バイト超 → ジャンボフレーム使用

---

## 比較機能

### キャプチャファイルの比較

**File → Merge**

**用途**:
- 問題発生前後のトラフィックを比較
- 異なる環境のキャプチャを並べて分析

**手順**:
1. 最初のキャプチャを開く
2. **File → Merge** で2つ目のキャプチャを選択
3. マージ方法を選択:
   - **Chronologically**: 時系列で統合
   - **Prepend**: 先頭に追加
   - **Append**: 末尾に追加

### 統計の比較

**ワークフロー例**:

**シナリオ**: パフォーマンス低下の原因調査

```
1. 正常時のキャプチャ（before.pcap）を開く
2. Statistics → HTTP → Requests で平均レスポンスタイムを確認
   → 平均 50ms

3. 問題発生時のキャプチャ（after.pcap）を開く
4. 同じ統計を確認
   → 平均 500ms（10倍）

5. 原因を特定:
   - Expert Information → TCP Retransmissionが増加
   - TCP Stream Graph → RTTが5倍に増加
   → ネットワーク遅延が原因
```

---

## 正規表現フィルタ

### 基本的な正規表現

```
# HTTPホストが .com で終わる
http.host matches "\\.com$"

# User-Agentに "Bot" または "bot" を含む
http.user_agent matches "(?i)bot"

# IPアドレスが 192.168.x.x
ip.src matches "^192\\.168\\."

# メールアドレスを含むHTTPペイロード
http contains "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
```

### 高度な正規表現フィルタ

```
# SSN（Social Security Number）を検出
frame contains "\\d{3}-\\d{2}-\\d{4}"

# クレジットカード番号を検出
frame contains "\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}"

# 日本の郵便番号を検出
frame contains "\\d{3}-\\d{4}"

# SQLインジェクションの試行を検出
http.request.uri matches "(?i)(union|select|insert|update|delete|drop|exec)"
```

**セキュリティ調査での活用**:
```
# 不審なファイル拡張子
http.request.uri matches "\\.(exe|bat|ps1|sh)$"

# Base64エンコードされたペイロード
frame contains "^[A-Za-z0-9+/]{40,}={0,2}$"

# IPv4アドレスを直接指定（DGAマルウェアの兆候）
dns.qry.name matches "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"
```

---

## マクロとLuaスクリプト

### Luaスクリプトによる拡張

StratoSharkはLuaスクリプトでカスタムディセクタやポストプロセッサを作成できます。

**スクリプト配置場所**:
```
~/.config/stratoshark/plugins/
/usr/share/stratoshark/plugins/
```

### カスタムプロトコルディセクタの例

```lua
-- custom_protocol.lua
-- カスタムプロトコルの解析

local custom_proto = Proto("custom", "Custom Protocol")

-- フィールド定義
local f_type = ProtoField.uint8("custom.type", "Type", base.DEC)
local f_length = ProtoField.uint16("custom.length", "Length", base.DEC)
local f_data = ProtoField.bytes("custom.data", "Data")

custom_proto.fields = {f_type, f_length, f_data}

-- ディセクタ関数
function custom_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CUSTOM"

    local subtree = tree:add(custom_proto, buffer(), "Custom Protocol")
    subtree:add(f_type, buffer(0,1))
    subtree:add(f_length, buffer(1,2))
    subtree:add(f_data, buffer(3))
end

-- ポート8888に登録
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(8888, custom_proto)
```

### ポストプロセッサの例

```lua
-- http_stats.lua
-- HTTPレスポンスタイムの統計

local http_times = {}

-- HTTPレスポンスを検出
local function collect_http_times()
    local tap = Listener.new("http")

    function tap.packet(pinfo, tvb)
        if pinfo.cols.info:lower():find("http/1.1 200") then
            local time = pinfo.rel_ts
            table.insert(http_times, time)
        end
    end

    function tap.draw()
        print("HTTP Response Times:")
        print(string.format("Count: %d", #http_times))

        if #http_times > 0 then
            table.sort(http_times)
            local median = http_times[math.floor(#http_times / 2)]
            print(string.format("Median: %.3f ms", median * 1000))
        end
    end
end

collect_http_times()
```

---

## リモートキャプチャ

### SSH経由でのキャプチャ

**方法1: GUIから直接**
```
1. Capture → Options
2. Manage Interfaces → Remote Interfaces
3. + ボタンをクリック
4. 設定:
   - Host: 192.168.1.100
   - Port: 22
   - Username: user
   - Remote Interface: eth0
5. Start をクリック
```

**方法2: sshdumpを使用**
```bash
# sshdumpツールを使ってリモートキャプチャ
sshdump --extcap-interface=sshdump \
  --remote-host 192.168.1.100 \
  --remote-port 22 \
  --remote-username user \
  --remote-interface eth0 \
  --fifo /tmp/remote.pcap

# StratoSharkで開く
stratoshark /tmp/remote.pcap
```

### Kubernetesからのリモートキャプチャ

```bash
# 方法1: kubectl execを使用
kubectl exec -n production nginx-pod-12345 -- \
  stratoshark -i any -w - | stratoshark -k -i -

# 方法2: ファイルに保存してからコピー
kubectl exec -n production nginx-pod-12345 -- \
  stratoshark -i any -w /tmp/capture.pcap -a duration:10

kubectl cp production/nginx-pod-12345:/tmp/capture.pcap ./pod-capture.pcap

stratoshark pod-capture.pcap
```

### クラウドインスタンスからのキャプチャ

**EC2インスタンス例**:
```bash
# SSH経由でキャプチャしてローカルで表示
ssh -i key.pem ec2-user@ec2-instance.amazonaws.com \
  "sudo tcpdump -i any -w - 'tcp port 80'" | stratoshark -k -i -
```

---

## パフォーマンス最適化

### 大規模キャプチャの扱い

**問題**: 10GB以上のキャプチャファイルを開くと遅い

**解決策1: 分割**
```bash
# editcapで分割
editcap -c 100000 large.pcap split.pcap

# 結果:
# split_00000_20250110103000.pcap
# split_00001_20250110103100.pcap
# ...
```

**解決策2: フィルタして抽出**
```bash
# 特定のIPアドレスのみ抽出
tshark -r large.pcap -Y "ip.addr == 192.168.1.100" -w filtered.pcap

# StratoSharkで開く
stratoshark filtered.pcap
```

**解決策3: サマリーモード**
```bash
# 統計情報のみ表示（GUIを開かない）
tshark -r large.pcap -q -z io,stat,1
tshark -r large.pcap -q -z conv,tcp
```

### メモリ使用量の削減

**Edit → Preferences → Protocols**

**無効化するプロトコル**:
```
☐ HTTP (不要な場合)
☐ TLS (復号化しない場合)
☐ SMB (使用しない場合)
```

**結果**: メモリ使用量が30-50%削減

### ディスプレイフィルタの最適化

**❌ 遅いフィルタ**:
```
# 文字列検索（すべてのパケットをスキャン）
frame contains "password"

# 正規表現（CPU負荷大）
http.host matches ".*\\.com$"
```

**✅ 速いフィルタ**:
```
# フィールド比較（インデックス利用）
tcp.port == 443

# 範囲指定
ip.addr == 192.168.1.0/24
```

---

## 実践的なトラブルシューティングシナリオ

### シナリオ1: Webサイトが遅い

**症状**: ブラウザでWebサイトを開くのに10秒かかる

**調査手順**:

**ステップ1: DNSを確認**
```
フィルタ: dns.qry.name == "slow-website.com"
```
結果: DNS応答は0.02秒 → DNS は問題なし

**ステップ2: TCP接続確立を確認**
```
フィルタ: tcp.port == 443 && tcp.flags.syn == 1
```
- SYNパケット送信: 0.000秒
- SYN+ACKパケット受信: 2.500秒 ← **2.5秒の遅延！**

**ステップ3: TCPストリームを追跡**
```
右クリック → Follow TCP Stream
```
観察: SYN再送信が3回発生

**ステップ4: RTTグラフを確認**
```
Statistics → TCP Stream Graphs → Round Trip Time Graph
```
結果: RTTが通常10ms → 2500msに急上昇

**根本原因**: サーバー側のファイアウォールが一時的にパケットをドロップ
**解決策**: ファイアウォールルールの見直し

### シナリオ2: APIが間欠的に失敗する

**症状**: APIが10回に1回失敗する（HTTP 500エラー）

**調査手順**:

**ステップ1: HTTP失敗パケットを抽出**
```
フィルタ: http.response.code == 500
```

**ステップ2: Expert Informationを確認**
```
Analyze → Expert Information → Error
```
発見: "TCP Retransmission" が500エラーの直前に発生

**ステップ3: TCPシーケンス分析**
```
Statistics → Flow Graph
```
観察:
```
Client → [POST /api/data] → Server
Client ← [TCP Retransmission] ← Server (失敗)
Client ← [HTTP 500] ← Server
```

**ステップ4: ウィンドウサイズを確認**
```
tcp.analysis.zero_window
```
結果: サーバー側のゼロウィンドウが頻発

**根本原因**: サーバーの受信バッファ不足
**解決策**: サーバーの `net.ipv4.tcp_rmem` を増やす

### シナリオ3: コンテナ間通信が断続的に切断される

**症状**: Kubernetes Pod間の通信が数秒ごとに切断される

**調査手順（StratoShark eBPF機能活用）**:

**ステップ1: Pod情報でフィルタ**
```
ebpf.k8s.pod == "app-pod-abc123"
```

**ステップ2: 切断パケットを検出**
```
tcp.flags.reset == 1
```

**ステップ3: プロセス情報を確認**
```
▼ eBPF Metadata
  ├─ Process Name: envoy ← Istio Sidecar
  ├─ Container ID: xyz789
  └─ Pod Name: app-pod-abc123
```

**ステップ4: Expert Informationを確認**
```
[Error] Connection Reset
  → Envoy proxyが接続をリセット
```

**ステップ5: Envoyログと相関**
```bash
kubectl logs app-pod-abc123 -c istio-proxy | grep "connection reset"
```
結果: `upstream_reset_before_response_started{connection_timeout}`

**根本原因**: Envoyのタイムアウト設定が短すぎる
**解決策**: VirtualServiceの `timeout` を60秒に延長

### シナリオ4: データベース接続プールの枯渇

**症状**: アプリケーションログに "Connection pool exhausted" が出力される

**調査手順**:

**ステップ1: DB接続を抽出**
```
tcp.port == 5432 && ip.addr == <db-server-ip>
```

**ステップ2: 会話統計を確認**
```
Statistics → Conversations → TCP
```
観察: 100個のTCP接続が確立されたまま（接続プールサイズ=100）

**ステップ3: 接続時間を測定**
```
tcp.time_relative
```
結果: 最も古い接続は3時間前から継続中

**ステップ4: アプリケーション層を確認**
```
Follow TCP Stream
```
観察: SQL SELECTは実行されているが、接続がcloseされていない

**根本原因**: アプリケーションの接続リークバグ
**解決策**: try-finally でDB接続を確実にクローズ

---

## トラブルシューティング

### 問題1: GUIが起動しない（macOS）

**症状**:
```
Error: Cannot open display
```

**解決策**:
```bash
# XQuartzをインストール
brew install --cask xquartz

# X11を起動
open -a XQuartz

# StratoSharkを起動
stratoshark
```

### 問題2: パケットが表示されない

**チェックリスト**:
- ✅ キャプチャフィルタが適用されていないか確認
- ✅ ディスプレイフィルタが適用されていないか確認
- ✅ インターフェースが正しく選択されているか確認

**解決策**:
```bash
# フィルタをクリア
Capture → Capture Filters → None
```

### 問題3: eBPFメタデータが表示されない

**症状**:
- プロセス情報が表示されない
- Kubernetes情報が表示されない

**解決策**:
```bash
# eBPF機能が有効か確認
stratoshark --version | grep eBPF

# 権限を確認
sudo stratoshark

# カーネルが対応しているか確認
uname -r  # 5.8以上が必要
```

---

## ベストプラクティス

### 1. 効率的なフィルタリング

**❌ 悪い例**:
```
# すべてのパケットを表示してから探す
（フィルタなし）
```

**✅ 良い例**:
```
# 最初から絞り込む
ip.addr == 192.168.1.100 && tcp.port == 443
```

### 2. 段階的な分析

**推奨フロー**:
```
1. 広いフィルタで概要把握
   → ip.addr == 192.168.1.100

2. プロトコルで絞り込み
   → ip.addr == 192.168.1.100 && http

3. 問題を特定
   → ip.addr == 192.168.1.100 && http.response.code >= 400

4. 詳細分析
   → Follow TCP Stream
```

### 3. 統計機能の活用

**効率的な調査**:
1. **Protocol Hierarchy** でトラフィック構成を把握
2. **Conversations** でトップトーカーを特定
3. **I/O Graph** で時系列変化を確認
4. 個別パケットの詳細分析

### 4. カラーリングの活用

**視認性向上**:
- 問題のあるパケットを赤で強調
- 重要なトラフィックを黄色で強調
- 正常なトラフィックはデフォルト色

---

## まとめ

本章では、StratoSharkのGUIを使った実践的な解析手法を学びました：

✅ **基本操作**: パケットリスト、詳細ペイン、バイトペインの使い方
✅ **フィルタリング**: ディスプレイフィルタの基本から高度な使い方
✅ **解析ワークフロー**: HTTP、TCP、TLS、DNS の実践的な調査手法
✅ **統計機能**: プロトコル階層、会話、エンドポイント、I/Oグラフ
✅ **eBPF拡張**: プロセス、コンテナ、Kubernetes情報の活用
✅ **エクスポート**: パケット、HTTPオブジェクト、TLS復号化
✅ **カスタマイズ**: カラム、カラーリング、タイムフォーマット
✅ **実践例**: レイテンシ調査、DNS障害、TLSエラー、Pod分析

次章では、Kubernetes環境に特化した統合機能を学びます。Pod単位のキャプチャ、Service Mesh解析、マルチクラスタ対応など、クラウドネイティブ時代のネットワーク解析手法を解説します。
