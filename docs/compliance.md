# ライセンス表示・SBOMの運用

## 今回作成した成果物

- `THIRD_PARTY_NOTICES.md`：MCP agent extraの実際の依存パッケージ29件、バージョン、宣言ライセンス、原文へのリンク。
- `third_party/licenses/`：導入済み配布物に含まれたLICENSE/COPYING/NOTICE/AUTHORS等を改変せず保存。
- `third_party/metadata/`：ライセンスと依存関係の根拠となるMETADATA。
- `third_party/license-manifest.json`：原文とMETADATAのSHA-256、ライセンス宣言の根拠。
- `sbom/python-agent.cdx.json`：CycloneDX 1.6、PURL、依存関係、宣言ライセンス、対象環境。
- `sbom/reference-artifacts.json`：同じバージョンの参照wheelとSHA-256。インストール済みバイナリの出自を証明するものではありません。
- `requirements-agent.lock`：対象環境の29依存物を固定。参照wheelがある場合はハッシュも固定。
- `sbom/external-integrations.json`：別途導入されるWazuh/osquery/ClamAVの範囲・条件。未確認のバージョンは推測しません。

このスナップショットは **macOS x86_64 / CPython 3.14.7 / agent extra** 向けです。
Windowsではpywin32等が追加されるため、このロックを全OS共通として使わないでください。
同じPythonパッケージのメタデータと依存条件でも、プラットフォーム別wheelには違う内包物があります。

SBOMはPythonパッケージ依存グラフの全体を対象にしています。
Wazuh/osquery/ClamAV、Python処理系、pip/setuptoolsなどのビルド・導入用ツール、
ネイティブwheelに内包されるOpenSSL/libffi/Rust crate等の個別コンポーネントはこのグラフに含めていません。
そのためCycloneDXの `compositions.aggregate` は `incomplete` とし、製品全体の完全なSBOMと誤認させません。
出荷物にそれらを含める場合は、実際の成果物・ビルドレシピに基づき別途追加します。

## ライセンスごとの表示方針

| 依存ライセンス | 配布時の扱い |
|---|---|
| MIT / BSD-3-Clause | 該当配布物の著作権・許諾条件・免責文を保持。BSDの名前による推奨禁止も維持 |
| MIT-0 | 自体にはMITの表示維持条件がないが、原文を証拠として保持 |
| Apache-2.0 | 原文、著作権表示、上流NOTICEが存在すれば保持。改変した場合は変更表示。独自にNOTICEの内容を創作しない |
| Apache-2.0 OR BSD-3-Clause | SBOMはORをそのまま記録。両原文を保持。配布方針でどちらの条件に従うか記録 |
| PSF-2.0 | typing-extensionsの同梱LICENSE全文（歴史的な複数許諾を含む）を保持 |
| MPL-2.0 | certifiの原文を保持し、対象ソースの取得方法を配布先へ案内。改変した対象ファイルはMPL条件に従って提供 |

certifi 2026.7.22 の対象ソースは
[PyPIの当該リリースのFiles](https://pypi.org/project/certifi/2026.7.22/#files) のSource Distributionから入手できます。
このURLを利用者向け案内にも保持し、実際の配布時にダウンロード可能なことを確認してください。
certifiを改変して配布する場合は、上流ソースだけでは足りず、その改変版を提供します。

表示だけではGPL対象の対応ソース提供やMPL対象ソース案内の義務は満たせません。
また宣言ライセンスがMITなどでも、バイナリ内包物の条件がすべて同じとは限りません。
ネイティブwheelを一体化する配布には別途バイナリ内包物の確認が必要です。

## 更新・検証手順

対象OS・Pythonのクリーンなvenvに、出荷するバージョンとagent extraを導入して実行します。
生成ツールはpackagingを使用し、未導入ならpip内のvendored packagingを使用します。
検証ツールにはjsonschema/referencingを使用します。ツール自体はアプリの実行依存物ではありません。

```sh
# インストール済みメタデータからバージョン一覧・原文・依存グラフを収集
.venv/bin/python scripts/generate_compliance.py
# その環境向けの参照wheelを取得（成果物の出自を記録するときはPyPI report等も保管）
.venv/bin/python -m pip download --no-deps --only-binary=:all: -r requirements-agent.lock --dest .compliance-wheels
# 参照wheelのSHA-256を追加
.venv/bin/python scripts/generate_compliance.py --wheels-dir .compliance-wheels
# 同じ環境・wheelでの再生成差分確認
.venv/bin/python scripts/generate_compliance.py --wheels-dir .compliance-wheels --check
# 公式CycloneDXスキーマをローカルに用意して構造・グラフ・表示原文ハッシュを検証
.venv/bin/python scripts/validate_compliance.py --schema-dir .compliance-schema
```

公式スキーマはCycloneDX specificationの1.6タグの `schema/` にある
`bom-1.6.schema.json`、`spdx.schema.json`、`jsf-0.82.schema.json` を使用します。
[公式仕様](https://github.com/CycloneDX/specification/tree/1.6/schema)
生成・検証は意図しない外部スキーマ取得をせず、既に取得したローカルファイルを使います。

第三者表示はwheelの `.dist-info/licenses/`、ソース配布には表示・原文・SBOM・更新ツールを収録します。
wheelのSBOMは外部添付用の `sbom/python-agent.cdx.json` を一緒に提供してください。
独自コードのライセンス（MIT）の `LICENSE` も、wheel の `.dist-info/licenses/` とソース配布に含まれます。
インストーラーや公開リリースは作成していません。

```sh
# build / setuptoolsはビルド用ツールとして別途導入
.venv/bin/python -m build --no-isolation --outdir .compliance-build
.venv/bin/python scripts/verify_distribution.py .compliance-build
```

検証用ビルドには build 1.6.1、setuptools 84.0.0、packaging 26.3、pyproject-hooks 1.3.3 を使いました。
これらはagent実行依存の29件に含まれません。Python処理系やビルドツール自体も配布する形に変更した場合は、
その出荷物について別のSBOMと第三者表示を作成してください。

更新時は以前の生成ディレクトリーをリリースごとに分けて保存するか、生成領域を空にしてから更新してください。
生成ツールは不要になった古いファイルを自動削除しません。`--check` は期待されるファイルの一致を検証し、余分なファイルの削除までは行いません。
各リリースのSBOM・表示・ロックは同一環境から同時に生成し、履歴を保存します。

ハッシュ付きロックはこの環境の参照wheel向けです。別OSのリリースは別のロック/SBOMを生成してください。
参照wheelのハッシュは出荷パッケージのハッシュではありません。
リリース時は、取得済みwheelから `pip install --no-index --find-links ... --require-hashes -r ...` で
新しいvenvへ導入し直して生成することで、出荷対象との対応をより明確にできます。

## OS別プロファイル

リポジトリ直下のロック・SBOM・第三者表示は **macOS x86_64 / CPython 3.14.7** の参照プロファイルで、
wheelに同梱する表示もこれです。ほかのOS向けは `profiles/<OS>-<CPU>-cp<版>/` に、同じ構成一式
（`requirements-agent.lock`、`sbom/`、`third_party/`、`THIRD_PARTY_NOTICES.md`）を置きます。

生成スクリプトは導入済み環境を読むため、各OSのプロファイルはそのOS上で作ります。
pipで別OS向けに解決しても `sys_platform` などの条件は実行中のOSで判定され、
Windowsだけの依存（pywin32など）を拾えないためです。

GitHub Actionsの「Compliance profiles」ワークフロー（`.github/workflows/compliance-profiles.yml`、手動実行）が、
Windows / Linux / macOS（arm64）それぞれで次を行い、結果を成果物（artifact）としてアップロードします。

1. 参照ロックと同じバージョンを制約にして、agent extraの依存をビルド済みwheelだけで導入
2. 導入したバージョンの参照wheelを取得
3. `generate_compliance.py --output profiles/<プロファイル名>` で生成
4. 固定したコミットのCycloneDX 1.6公式スキーマで `validate_compliance.py` を実行

ライセンス表記を確定できない依存があると生成は失敗扱いになりますが、成果物は人が確認できるようアップロードします。
表記の確定は法的な判断なので、生成ツールは推測で埋めません。成果物を `profiles/` に取り込み、
確認した結果とあわせてコミットしてください。

この手順は、ローカルのmacOS x86_64で実行すると、リポジトリ直下の参照プロファイルを1バイトも違わず再生成できることを確認しています。

### 現在のプロファイル（2026-10-12 生成）

| 置き場所 | 環境 | パッケージ | 検証 |
|---|---|---|---|
| リポジトリ直下 | macOS x86_64 / CPython 3.14.7（ローカル生成、参照） | 29 | 合格 |
| `profiles/darwin-arm64-cp314/` | macOS arm64 / CPython 3.14.7 | 29 | 合格 |
| `profiles/linux-x86_64-cp314/` | Linux x86_64 / CPython 3.14.8 | 29 | 合格 |
| `profiles/windows-amd64-cp314/` | Windows AMD64 / CPython 3.14.7 | 30（pywin32 312 を含む） | **未合格**：pywin32 のライセンス表記が未確定 |

- 4つとも同じバージョンです（Windows の pywin32 を除く）。macOS arm64 と Linux のライセンス原文は参照と完全に同じです。
- Windows の pydantic-core と rpds-py の LICENSE は、内容は同じで改行コードだけが CRLF です（Windows 向け wheel の中身どおり）。
  原文はバイト単位でハッシュを記録しているため、`.gitattributes` で改行コードの変換を禁止しています。
- pywin32 のメタデータは `License: PSF` だけで、同梱の原文は部品ごとに異なります：本体（win32・COM・Pythonwin）は
  Mark Hammond の BSD 形式、adodbapi は LGPL 2.1、MAPIStubLibrary は MIT 形式、Scintilla は HPND 形式、idle は PSF と HPND 形式。
  原文はすべて `profiles/windows-amd64-cp314/third_party/licenses/pywin32/` に保存してあります。
  ライセンス表記（SPDX 式）と LGPL 部分の扱いを所有者が判断するまで、Windows 版は `validate_compliance.py` に合格しません。

## 配布に進む前の未確定事項

1. （完了）独自コードのライセンス：2026-10-12 に MIT を適用（著作権者 tedorigawa001）。
2. Windows 版プロファイルの pywin32 のライセンス表記の確定（Linux・macOS arm64 は生成・検証済み）。
3. 単体wheel/sdist配布か、Pythonや依存wheelを含む実行ファイル/インストーラー配布かを確定。
4. 同梱するネイティブ依存物のバージョン・ライセンス・対応ソース要件を実物で確認。
5. Wazuh/ClamAV等を同梱する場合、GPL対応ソース等を準備し、結合形態を確認。

今回の成果物はバージョンと権利表示を追跡する基盤です。ライセンスの適法性判定や脆弱性スキャンの代替ではありません。
