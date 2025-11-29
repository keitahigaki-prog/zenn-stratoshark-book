# StratoShark入門 — eBPF時代のWireshark

このリポジトリは、Zenn Bookの「StratoShark入門 — eBPF時代のWireshark」の原稿を管理しています。

## 📖 本について

**Wiresharkの作者Gerald Combs氏とSysdig/Falco創設者Loris Degioanni氏が協働**して開発した次世代のパケット/イベント解析ツールStratoSharkを学ぶ本です。eBPFを活用したクラウドネイティブ時代のネットワーク解析手法を、基礎から実践まで体系的に解説します。

### 対象読者

- SREエンジニア
- ネットワークエンジニア
- セキュリティエンジニア
- Kubernetes管理者
- パフォーマンスチューニング担当者

### 関連書籍

本書の姉妹本として、同じ著者による以下の書籍もあります：
- [**Falco実践シリーズ - Kubernetesランタイムセキュリティの実装ガイド**](https://zenn.dev/books/falco-practice-series)

**使い分け**:
- **Falco**: システムコール監視によるランタイムセキュリティ
- **StratoShark**: ネットワークパケット解析とトラブルシューティング

両方を組み合わせることで、Kubernetesの包括的なセキュリティ・可観測性を実現できます。

## 📚 目次

1. StratoSharkとは？ ― 新世代のパケット／イベント解析ツール
2. Wiresharkとの違い ― なぜStratoSharkが生まれたのか？
3. 内部アーキテクチャ ― eBPFとイベントドリブンの設計
4. インストールとセットアップ
5. CLIでのキャプチャ ― stratoshark capture の基本操作
6. GUI視点での解析 ― WiresharkライクなUIと新機能
7. Kubernetes と StratoShark ― Pod単位でのキャプチャ
8. SRE実務での利用例 ― トラブルシュート事例集
9. eBPFエコシステム統合 ― Falco、Sysdig、Ciliumとの連携
10. クラウド時代のネットワーク解析 ― StratoSharkの未来

## 🚀 開発環境

このリポジトリは[Zenn CLI](https://zenn.dev/zenn/articles/zenn-cli-guide)を使用しています。

### セットアップ

```bash
# リポジトリをクローン
git clone https://github.com/YOUR_USERNAME/zenn-stratoshark-book.git
cd zenn-stratoshark-book

# プレビューサーバーを起動
npx zenn preview
```

ブラウザで http://localhost:8000 にアクセスすると、プレビューが表示されます。

## 📝 執筆状況

- [x] 第1章: StratoSharkとは？
- [x] 第2章: Wiresharkとの違い
- [x] 第3章: 内部アーキテクチャ
- [ ] 第4章: インストールとセットアップ
- [ ] 第5章: CLIでのキャプチャ
- [ ] 第6章: GUI視点での解析
- [ ] 第7章: Kubernetes と StratoShark
- [ ] 第8章: SRE実務での利用例
- [ ] 第9章: Falco / eBPF セキュリティとの比較
- [ ] 第10章: クラウド時代のネットワーク解析

## 🔗 リンク

- [StratoShark公式サイト](https://www.stratoshark.org/)
- [Wireshark公式サイト](https://www.wireshark.org/)
- [eBPF.io](https://ebpf.io/)

## 📄 ライセンス

本書の内容は著作権で保護されています。