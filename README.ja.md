# Personal PC Scanner MCP

[![CI](https://github.com/tedorigawa001/PersonalPCScanner-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/tedorigawa001/PersonalPCScanner-MCP/actions/workflows/ci.yml)

[English](README.md) | **日本語**

個人PC（Windows / macOS / Linux）の状態を、AIエージェントから**読み取り専用で**確認するための MCP サーバーです。
定評のあるオープンソースの検査ツール（osquery・ClamAV・Wazuh）を呼び出し、結果を AI が扱いやすい JSON で返します。

> [!IMPORTANT]
> このツールは **「PCが安全である」と判定するものではありません**。
> 所見が0件でも、検査範囲の不足・定義ファイルの古さ・インベントリ未生成などの可能性があります。
> 結果は「観測した事実」として扱い、最終判断は PC の所有者が行ってください。

## 目次

- [概要](#概要)
- [仕組み](#仕組み)
- [提供する機能](#提供する機能)
- [必要なもの](#必要なもの)
- [セットアップ](#セットアップ)
- [設定項目](#設定項目)
- [結果の読み方](#結果の読み方)
- [制限事項](#制限事項)
- [安全のための設計](#安全のための設計)
- [テスト](#テスト)
- [関連ドキュメント・ライセンス](#関連ドキュメントライセンス)

## 概要

**できること**

- OS のバージョン、インストール済みアプリ、待受ポートの一覧を取得する（osquery）
- 所有者が許可したフォルダーだけをマルウェア検査する（ClamAV）
- Wazuh に登録済みの端末について、検出済みの脆弱性（CVE）を取得する（Wazuh indexer）
- 上記を AI エージェントの MCP ツール、またはコマンドライン（CLI）から実行する

**しないこと**

- ファイルの削除・隔離・修復などの変更（すべて読み取り専用です）
- リアルタイム保護、自動隔離、EDR としての機能
- 独自のソフトウェア名と CVE の照合
- 検査エンジンや定義ファイルの同梱・更新（それぞれ公式配布元から導入・更新してください）

使いたいエンジンだけを設定すれば動きます。たとえば Wazuh なしで osquery と ClamAV だけを使うこともできます。

## 仕組み

```text
AIクライアント（Claude Desktop など）
   │  MCP（stdio。ネットワークに待受ポートは開きません）
   ▼
Personal PC Scanner（このプロジェクト）
   ├─ osqueryi ……………… OS・アプリ・待受ポートの一覧
   ├─ clamscan ……………… 許可したフォルダーのマルウェア検査
   └─ Wazuh indexer ……… 登録済み端末の既存の脆弱性情報（HTTPS）
```

AI が指定できるのは「どの固定クエリを使うか」「どの許可フォルダーを検査するか」だけです。
任意の SQL・任意のパス・実行ファイル・接続先は、AI から変更できません。

## 提供する機能

| MCPツール | CLIコマンド | 使うエンジン | 内容 |
|---|---|---|---|
| `scanner_status()` | `status` | なし | 設定の有無を表示します。エンジンの動作や安全性は確認しません |
| `collect_inventory(query_id, offset=0)` | `inventory <query_id> [--offset N]` | osqueryi | `os_version`・`applications`・`listening_ports` のいずれかを取得します |
| `scan_malware(root_alias, relative_path=".")` | `malware <root_alias> [relative_path]` | clamscan | 許可フォルダー（またはその中のパス）を検査します |
| `get_vulnerabilities(offset=0)` | `vulnerabilities [--offset N]` | Wazuh indexer | 設定した1台の端末の脆弱性を、深刻度の高い順に取得します |
| — | `serve` | — | MCP サーバーとして起動します |

`listening_ports` は、待受アドレス（`0.0.0.0` なら全インターフェースに公開、`127.0.0.1` なら自PCのみ）とプロセス名も返します。

AI クライアントには、`query_id` の選択肢と許可フォルダーのエイリアスがツールの定義として伝わるため、AI は有効な値を選べます。

## 必要なもの

- **Python 3.11 以上**
- **使いたい検査エンジン**（いずれも任意。使うものだけ）
  - [osquery](https://osquery.io/downloads/)：インベントリ取得用
  - [ClamAV](https://docs.clamav.net/manual/Installing.html)：マルウェア検査用。定義ファイルは `freshclam` で利用者自身が更新します
  - Wazuh：脆弱性取得用。**PC に Wazuh エージェントを入れるだけでは動きません**。
    別途 Linux などで Wazuh server / indexer を用意し、PC のエージェントを登録して、脆弱性検出を有効にしておく必要があります
- **MCP で使う場合**：Python 用 MCP SDK v1（下記の `agent` extra で入ります）

## セットアップ

### 1. 検査エンジンを導入する

使いたいエンジンを公式配布元から導入します。ClamAV は導入後に一度 `freshclam` を実行し、定義ファイルを取得してください。

インストール先は次のコマンドで調べられます（あとで設定ファイルに書きます）。

```sh
# macOS / Linux
which osqueryi clamscan
```

```powershell
# Windows
where.exe osqueryi clamscan
```

インストール先の例（導入方法によって異なります）：

| OS | osqueryi | clamscan |
|---|---|---|
| Windows | `C:\Program Files\osquery\osqueryi.exe` | `C:\Program Files\ClamAV\clamscan.exe` |
| macOS | `/usr/local/bin/osqueryi` | `/opt/homebrew/bin/clamscan`（Homebrew・Apple シリコン） |
| Linux | `/usr/bin/osqueryi` | `/usr/bin/clamscan` |

### 2. このプロジェクトを導入する

macOS / Linux：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[agent]'
```

Windows（PowerShell）：

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install ".[agent]"
```

CLI だけを使う場合は `[agent]` は不要です。導入せずに、プロジェクトのフォルダーで `python -m pc_scanner.cli` を直接実行することもできます。

### 3. 設定ファイルを作る

`scanner.example.toml` を `scanner.toml` にコピーし、エンジンの絶対パスと、検査を許可するフォルダーを書きます。

```toml
[local]
osquery_binary = '/usr/local/bin/osqueryi'
clamav_binary = '/opt/homebrew/bin/clamscan'

[scan_roots]
# 「エイリアス = 絶対パス」。AI はエイリアスでしか指定できません
downloads = '/Users/you/Downloads'
```

- パスは**単一引用符**で囲むのがおすすめです。Windows の `\` もそのまま書けます（例：`'C:\Users\you\Downloads'`）。
- 空欄にしたエンジンは無効になります。
- この設定ファイルは所有者だけが編集し、AI には編集させないでください。

### 4. 動作を確認する

```sh
.venv/bin/python -m pc_scanner.cli --config scanner.toml status
.venv/bin/python -m pc_scanner.cli --config scanner.toml inventory os_version
.venv/bin/python -m pc_scanner.cli --config scanner.toml malware downloads
```

Windows では `.venv/bin/python` を `.venv\Scripts\python.exe` に置き換えてください。
結果は JSON で表示されます（読み方は[結果の読み方](#結果の読み方)を参照）。

### 5. AI クライアントに登録する

MCP（stdio）に対応したクライアントの設定に、次と同等の内容を登録します。書式はクライアントごとに確認してください。

```json
{
  "mcpServers": {
    "personal-pc-scanner": {
      "command": "/absolute/path/to/project/.venv/bin/python",
      "args": ["-m", "pc_scanner.cli", "--config", "/absolute/path/to/project/scanner.toml", "serve"]
    }
  }
}
```

- Windows では `command` を `C:\\path\\to\\project\\.venv\\Scripts\\python.exe` のようにします（JSON では `\` を `\\` と書きます）。
- 手順2でパッケージを導入済みなので、作業フォルダー（`cwd`）の指定は不要です。
- この基盤自体は、特定の AI サービスの API キーを必要としません。

### Wazuh を使う場合

`scanner.toml` の `[wazuh]` に次を設定します。

```toml
[wazuh]
url = 'https://indexer.example:9200'   # indexer の HTTPS アドレス（管理 API のポート 55000 ではありません）
agent_id = '001'                        # Wazuh 上の端末 ID。'1' と書いても '001' として扱います
ca_file = '/path/to/root-ca.pem'        # indexer の CA 証明書
```

ユーザー名とパスワードは**設定ファイルに書かず**、環境変数で渡します。

```sh
export PC_SCANNER_WAZUH_USER='reader'
export PC_SCANNER_WAZUH_PASSWORD='...'
```

MCP で使う場合は、クライアントの秘密情報管理機能や起動元の環境から渡してください。
indexer のアカウントには、対象端末の脆弱性インデックスへの**読み取り権限だけ**を付与し、管理者アカウントは使わないでください。

### うまく導入できないとき

- **`cryptography` のビルドに失敗する**：ビルド済みパッケージに限定して導入します。Intel Mac（x86_64）では、
  最新の `cryptography` にビルド済みパッケージがなく、ソースからのビルドになるため発生します。

  ```sh
  .venv/bin/python -m pip install --only-binary=cryptography '.[agent]'
  ```

- **依存パッケージのバージョンを固定したい**：`requirements-agent.lock` は、ハッシュ付きで依存を固定したロックファイルです。
  ただし **macOS x86_64 / CPython 3.14.7 専用**で、他の環境では使えません。

  ```sh
  .venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-agent.lock
  .venv/bin/python -m pip install --no-deps .
  ```

## 設定項目

| 項目 | 説明 | 既定値 |
|---|---|---|
| `local.osquery_binary` | osqueryi の絶対パス。空欄なら無効 | 空欄 |
| `local.clamav_binary` | clamscan の絶対パス。空欄なら無効。`.bat` / `.cmd` は使えません | 空欄 |
| `local.timeout_seconds` | 1回の操作の制限時間（1〜3600秒）。ClamAV ではフォルダー確認と検査の合計、Wazuh は最大30秒です | `600` |
| `local.max_output_bytes` | エンジン出力の上限（1024〜8388608 バイト） | `1048576` |
| `scan_roots.<エイリアス>` | 検査を許可するフォルダー（絶対パス）。エイリアスは英数字・`_`・`-` で64文字まで | なし |
| `wazuh.url` | Wazuh indexer の HTTPS アドレス。空欄なら無効 | 空欄 |
| `wazuh.agent_id` | 対象端末の数字の ID | 空欄 |
| `wazuh.ca_file` | indexer の CA 証明書。空欄ならシステムの証明書を使います | 空欄 |
| 環境変数 `PC_SCANNER_WAZUH_USER` / `PC_SCANNER_WAZUH_PASSWORD` | Wazuh の認証情報 | — |

## 結果の読み方

すべての操作が、同じ形の JSON を返します。

```json
{
  "schema_version": 1,
  "source": "clamav",
  "status": "partial",
  "observed_at": "2026-10-12T05:00:00+00:00",
  "findings": [{"kind": "malware", "severity": "high", "path": "sub/file.exe", "signature": "..."}],
  "warnings": ["Signature-based detection only; no detection does not prove safety"],
  "data": {"root_alias": "downloads", "unreadable_directories": ["locked"]}
}
```

`observed_at` は結果を取得した時刻（UTC）です。

### status（実行結果）

| status | 意味 | 扱い方 |
|---|---|---|
| `completed` | 操作は最後まで完了しました | **PC が安全という意味ではありません** |
| `partial` | 一部しか確認できていません（読めないフォルダー、上限到達、結果が0件、ページの途中など） | `warnings` を確認してください。検査範囲は不完全です |
| `error` | 実行できませんでした（未設定、権限不足、タイムアウト、接続失敗など） | 未検査として扱ってください |

### CLI の終了コード

| 終了コード | 意味 |
|---|---|
| `0` | 完了し、所見なし |
| `1` | 完了し、所見あり（マルウェア・脆弱性など） |
| `2` | `partial` または `error`。**所見があっても `partial` なら 2 になります** |

### 件数が多いとき（ページング）

インベントリと Wazuh の結果は、1回500件ずつ返します。続きがあると `data.next_offset` に数値が入るので、
その値を `offset`（CLI では `--offset`）に渡してもう一度実行してください。
1ページ分だけの結果や、2ページ目以降は `partial` になります。`offset` の上限は 9500 です（OpenSearch の既定の取得上限 10000 件に合わせています）。

## 制限事項

### 検査範囲

- アプリ一覧は OS 標準の情報源のみです。ポータブルアプリ、言語のパッケージ、ブラウザー拡張などは含みません。
- 通常ユーザーで実行すると、待受ポートの一覧から他ユーザーやシステムのものが欠けることがあります。
- 待受ポートのうち、ポート0（UNIX ソケットなど）は除外しています。

### ClamAV の上限

| 上限 | 値 |
|---|---|
| ファイルサイズ | 100MB |
| アーカイブ展開後の合計 | 200MB |
| アーカイブの入れ子 | 16段 |
| フォルダーの深さ | 検査対象のフォルダーを1段目として16段 |

- 上限を超えたファイルは `scan_limit` という所見として、マルウェアとは区別して報告します。
- 深さの上限を超えるフォルダーがある場合も、それまでに見つかった所見は残したまま `partial` を返します。
- シンボリックリンクは辿りません。Windows のジャンクションはフォルダーの深さの確認から除外していますが、
  clamscan 自体がジャンクションを辿るかどうかは、環境ごとに確認が必要です。
- 読めないフォルダーがあっても検査は続け、`data.unreadable_directories`（最大20件）に記録して `partial` を返します。
- 未対応の形式、暗号化されたファイル、古い定義ファイルなどでは検出できないことがあります。
- clamscan は毎回定義ファイルを読み込むため、制限時間を短くするとタイムアウトしやすくなります。

### Wazuh

- 取得するのは Wazuh に**すでに保存されている**情報です。鮮度や、PC が今オンラインかどうかは保証しません。
- 対象端末の記録が0件のときは、端末 ID の誤り・未登録・未検査と区別できないため `partial` を返します。
  端末の ID・名前・登録状況と収集時刻を、Wazuh 側で確認してください。

### プライバシー

- クラウドの AI に結果を渡すと、アプリ名・プロセス ID・ファイル名などが送信されることがあります。送信先と範囲は PC の所有者が決めてください。
- 送信量を減らすため、ファイルのパスは許可フォルダーからの相対パスで返し、エンジン出力中の絶対パスは `<エイリアス>` に置き換えます。
- エンジン出力は先頭と末尾の計60行に縮め、500文字を超える行も前後を残して縮めます（縮めた場合は `data.engine_text_truncated` が true）。所見は500件まで（マルウェアを優先）です。

### 動作上の前提

- 管理者権限ではなく、**通常ユーザー**で実行してください。自動で権限を昇格することはありません。
- フォルダーの制限は OS のサンドボックスではありません。悪意のあるローカルユーザーによるファイルの差し替えなどは防げません。
- タイムアウト・出力上限・キャンセルのときは、エンジンが起動した子プロセスもまとめて停止します
  （macOS / Linux はプロセスグループ、Windows は Job Object）。エンジンが正常に終了した後に残ったプロセスも停止します。
  ただし、自分からグループを抜けたプロセス（macOS / Linux で新しいセッションを始めたものなど）は止められません。
  そのプロセスがエンジンの出力を開いたままにした場合は、エラーになります。

## 安全のための設計

- **固定の操作だけ**：任意の SQL・パス・実行ファイル・接続先・端末 ID を AI から指定できません。
- **読み取り専用**：ファイルの削除や隔離を行うオプションは使いません。全ツールに読み取り専用の注釈（`readOnlyHint`）を付けています。
  クライアントによってはこの注釈を理由に承認なしで実行するため、毎回承認したい場合はクライアント側で設定してください。
- **シェルを使わない**：エンジンはシェルを介さずに直接起動します。Windows の `.bat` / `.cmd` は起動しません。
- **認証情報を渡さない**：エンジンに渡す環境変数は、パスに関するもの（Windows の `USERPROFILE`・`PROGRAMDATA` など）だけです。
- **通信を限定**：Wazuh への接続は HTTPS のみで、証明書の検証は無効にできません。プロキシとリダイレクトも使いません。
- **AI の指示を信用しない**：結果に含まれるファイル名やアプリ名は信用できない文字列として扱うよう、AI に指示しています。
- **長時間の検査でも止まらない**：検査は別スレッドで実行し、エンジンは1つずつ順番に動かします。
  検査中は10秒ごとに進捗を通知するので、進捗でタイムアウトを延長するクライアントなら長い検査も待てます。
- **キャンセルで止まる**：AI クライアントが要求をキャンセルすると、実行中のエンジンとその子プロセスを約0.1秒以内に停止します。
  順番待ちの検査は開始されません。
- **文字化け対策**：Windows でエンジンの出力が UTF-8 でない場合は、システムの既定の文字コード（日本語版では cp932）で読み直します。

## テスト

[手順2](#2-このプロジェクトを導入する)で作った仮想環境の Python で実行します。

macOS / Linux：

```sh
.venv/bin/python -m unittest discover -s tests -v
```

Windows（PowerShell）：

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

- テストは、エンジンの出力と Wazuh の応答を模したデータで、境界値や失敗時の扱いを確認します。
- MCP のテスト4件には `agent` extra が必要です。システムの `python3` など、未導入の Python で実行するとスキップされます。
  実際にサーバーを起動して接続・ツール一覧・呼び出しを確認し、長時間の検査中の応答・順番待ち・進捗通知はメモリ内の接続で確認します。
- GitHub Actions が、`main` への push とプルリクエストのたびに、Windows / macOS / Linux × Python 3.11 / 3.14 でテストを実行します。
  `agent` extra を導入するので、MCP のテストもスキップされません。あわせて wheel と sdist をビルドし、
  第三者表示と SBOM が含まれていることを確認します。Windows では本物のジャンクションや、ACL で読み取りを拒否した
  フォルダー（`Documents\My Music` のようなジャンクションを含む）を作り、検査での扱いを確認します。
- 実際のエンジンでの検出精度や、各 OS での動作は保証していません。配布前に、各 OS の実機での受入試験が必要です。

## 関連ドキュメント・ライセンス

- [docs/backlog.md](docs/backlog.md)：未対応の課題と、実機で確認すべき項目
- [docs/licensing.md](docs/licensing.md)：ライセンス方針と配布前チェック
- [docs/compliance.md](docs/compliance.md)：SBOM・第三者表示の対象範囲と再生成手順
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)・[CycloneDX SBOM](sbom/python-agent.cdx.json)：MCP 用 Python 依存パッケージの表示

独自コードのライセンスは [MIT を提案](docs/license-recommendation.md)していますが、まだ正式には適用していません。
このリポジトリは Wazuh・osquery・ClamAV のコード、バイナリ、ルール、定義ファイルを含みません。
