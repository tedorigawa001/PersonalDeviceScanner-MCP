# 独自コードのライセンス

2026-10-12。現在の「OSSを同梱せず、別導入されたCLI/APIへ接続する」構成には **MIT** を推奨します。
この提案は独自コードに対するものです。第三者コンポーネントのライセンスは変更しません。
**2026-10-12 に MIT を正式に適用しました。著作権者は tedorigawa001、本文はリポジトリ直下の [LICENSE](../LICENSE) です。**

| 候補 | 適性 | 注意点 |
|---|---|---|
| MIT（推奨） | 個人利用、OSS公開、商用配布、将来の派生物で使いやすい。表示条件が簡潔 | 著作権・許諾・免責文を維持。明示的な特許許諾条項なし |
| Apache-2.0 | 特許許諾と特許訴訟時の終了条件を明記したい場合 | GPLv2-onlyと結合して派生物になる場合の互換性に制約。変更表示・NOTICEの条件も確認 |
| GPL-2.0-only | 独自コードの派生物もGPLで公開する方針なら候補 | 現在の全Python依存物をGPLv2で結合できるとは限らない。python-multipart等はApache-2.0 |

MITは改変版の公開を要求しません。ソース公開や商用販売の両方を選べます。
ただしMITを選んでも、Wazuh/ClamAVのGPL義務を回避できるわけではありません。
GPLv2と結合して派生物になる場合の全体の条件は、コード・データ・依存物・配布方法を対象に別途判断します。
「MITなら依存関係もすべてGPLv2互換」という意味ではありません。
第三者のApache-2.0部分も含めたGPLv2-onlyでの一体化は避け、現状の独立した接続境界を維持してください。

## 適用内容（2026-10-12）

- 提案していた公式MIT本文のテンプレート（`docs/LICENSE-MIT.proposed.txt`）の著作権者欄を
  `tedorigawa001` に置き換え、リポジトリ直下の `LICENSE` にしました。本文はほかに変えていません。
- `pyproject.toml` に `license = "MIT"` を追加し、`license-files` に `LICENSE` を加えました。
  wheel のメタデータには `License-Expression: MIT` が入り、`LICENSE` は wheel と sdist の両方に含まれます。
- SBOM を再生成し、プロジェクト自身のライセンスを `MIT` として記録しました。
- 独自Pythonソースへの `SPDX-License-Identifier: MIT` は付けていません（任意）。
- 第三者ファイルへ独自のMIT表示を上書きしないでください。

配布物には独自コードの `LICENSE`、`THIRD_PARTY_NOTICES.md`、`third_party/licenses/` を含めます。
MITだけの独自 `NOTICE` は必須ではありません。第三者のNOTICE/AUTHORS/COPYRIGHTは存在すれば原文を保持します。
Pythonパッケージのwheel/sdistに第三者表示が入るよう設定しています。
今回の依存関係にはMPL-2.0のcertifiも含まれるため、ソースの入手案内も必要に応じて添付します。

## 根拠

- [OSIのMITライセンス本文](https://opensource.org/license/mit)
- [Apache Software Foundation：GPL互換性](https://apache.org/licenses/GPL-compatibility.html)
- [GNU：GPLv2 FAQ、他ライセンスとの互換性](https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.html)
- [Mozilla：MPLの配布条件](https://www.mozilla.org/en-US/MPL/2.0/FAQ/)

表示・SBOMの範囲と更新手順は [compliance.md](compliance.md) を参照してください。
