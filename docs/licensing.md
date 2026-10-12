# OSSライセンスと配布方針

確認日: 2026-10-12。公式のライセンス・文書を基にした初期設計上の整理です。
ライセンス適合はバージョン、組み合わせ、配布方式、含まれるファイルで変わります。
この文書は将来の配布物全体について「違反がない」と保証するものではありません。

| コンポーネント | 確認した主ライセンス | 初期版の接続方法 |
|---|---|---|
| Wazuh | GPL version 2、ファイル別の例外あり | 別途運用されるindexerへのHTTPS検索 |
| osquery | Apache-2.0 **OR** GPL-2.0-only。利用者は選択可能 | 別途導入したosqueryiを別プロセスで呼ぶ |
| ClamAV | GPL version 2。内包物の個別条件も確認が必要 | 別途導入したclamscanを別プロセスで呼ぶ |
| MCP Python SDK v1 | MIT | agent extraとしてインストール。依存物は個別確認 |

## 現在の構成

本リポジトリは上流コード・バイナリ・シグネチャ・Wazuhルールをコピーしていません。
osqueryのSQLは本プロジェクト独自の短いクエリです。ClamAVのライブラリをリンクしません。
OSSの自動ダウンロード・統合インストーラーも作成していません。
この構成は同梱由来の義務を避けるための設計判断であり、別プロセス/APIという理由だけで
独立著作物であると断定するものではありません。

特にWazuhのLICENSEは、ソース/データ取り込みに加え、proprietary executable installerへの
統合・同梱等を派生物と解釈する旨を記載しています。再配布に適用される説明なので、
将来の独自インストーラーにWazuhを含める前に実物を対象として確認する必要があります。
ライセンスを理由に商用利用そのものを禁止しているわけではありません。

本プロジェクト独自コードには [MITを推奨](license-recommendation.md) し、本文の提案を用意しています。
依頼範囲が提案であるため、正式な許諾と著作権者の確定はまだ行っていません。
プロプライエタリ配布の可否は連携形態と含有物のレビューで判断します。
GPLに合わせて公開する方針を選んでも、第三者著作権表示・対応ソース・個別依存ライセンスの義務は別途残ります。

## 配布物を作る前に行うこと

1. 実際に採用するOSSのリリース/コミット、入手元、ハッシュ、LICENSE、NOTICEを記録します。
   上記のmain/masterの確認だけで、配布するバージョンのレビューを代替しません。
2. 本基盤のみを配布するか、各OSS・Python/MCPの依存物も同梱するかを確定します。
   インストーラーやコンテナに含めれば、別プロセスでも再配布として確認します。
3. GPL対象バイナリを再配布する場合、完全な対応ソース、ビルドに必要な情報、ライセンス・著作権表示を整えます。
   単なる上流URLの添付では充足と断定できません。改変表示とソース提供方法も確認します。
4. osqueryでApache-2.0を選択する場合、その条件と同梱依存物のライセンスを確認し、必要なLICENSE/NOTICE等を保持します。
5. ClamAV定義ファイル、Wazuhルール、フィードや付属データを配布する場合、その配布物固有の条件と更新サービスの規約を確認します。
6. Python/MCPを含む全依存物のSBOM、ライセンス一覧、必要な帰属表示を配布形態ごとに生成します。
   optional dependencyの範囲指定は再現可能な配布ロックではありません。配布ビルドではバージョンを固定します。
7. 独自コードのライセンス、第三者表示、商標・ロゴ使用、配布契約の整合を確認します。
   商用/非公開配布で派生物性の判断が必要な場合、実際の成果物をライセンス専門家に確認します。

## 公式確認元

- [Wazuh LICENSE](https://github.com/wazuh/wazuh/blob/master/LICENSE)
- [osquery ライセンス選択](https://github.com/osquery/osquery/blob/master/LICENSE)
- [osquery Apache-2.0](https://github.com/osquery/osquery/blob/master/LICENSE-Apache-2.0)
- [ClamAV ライセンス説明](https://docs.clamav.net/)
- [ClamAV COPYING.txt](https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt)
- [MCP SDK v1 LICENSE](https://github.com/modelcontextprotocol/python-sdk/blob/v1.x/LICENSE)
- [Wazuh indexer API use cases](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html)
- [osqueryi](https://osquery.readthedocs.io/en/stable/introduction/using-osqueryi/)
- [ClamAV scanning](https://docs.clamav.net/manual/Usage/Scanning.html)

Python agent依存物のSBOM、原文の第三者表示、更新・検証ツールを整備しました。
対象範囲・残る配布前作業は [compliance.md](compliance.md) を参照してください。
OS別受入試験、署名DBの鮮度取得、Wazuhの端末稼働/収集時刻チェック、ページングは今後の機能追加です。
