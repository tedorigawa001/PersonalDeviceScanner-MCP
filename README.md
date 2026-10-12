# Personal PC Scanner — 初期版

Windows / macOS / Linux の個人PCを対象にした、AIエージェント向けOSS連携基盤です。
Python 3.11以上。CLI部分は標準ライブラリのみ、MCP接続には任意の `mcp` v1 SDKを使います。
このリポジトリはWazuh・osquery・ClamAVのコード、バイナリ、ルール、定義ファイルを同梱しません。

## できること

| 操作 | 連携 | 意味 |
|---|---|---|
| `status` | この基盤 | 設定の有無のみ。導入・稼働・安全性の検証ではありません |
| `inventory` | osqueryi | OS、アプリ一覧、待受ポート（待受アドレス・プロセス名付き）の固定SQLによる観測 |
| `malware` | clamscan | 明示的に許可したフォルダー内のシグネチャ検査 |
| `vulnerabilities` | Wazuh indexer HTTPS API | 設定した1台の既存CVEインベントリを取得 |
| `serve` | MCP stdio | 上記4操作をAIエージェントのツールとして公開 |

WazuhのエージェントだけではCVE取得は動きません。別途Linux上などにWazuh server / indexerを
用意し、PCのエージェントを登録し、システムインベントリ・脆弱性検出を設定してください。
この基盤は検出エンジンやEDRそのものではなく、自動隔離・リアルタイム保護・修復・
独自のソフトウェア名/CVE照合は実装していません。WazuhなしでもosqueryとClamAVは個別に利用可能です。

## 導入

1. [osquery](https://osquery.io/downloads/) と [ClamAV](https://docs.clamav.net/manual/Installing.html) をそれぞれ公式配布元から導入します。
   ClamAVは利用者側でfreshclamと定義ファイルの保存先を設定・更新します。この基盤は更新を実行しません。
2. `scanner.example.toml` を `scanner.toml` にコピーし、実行ファイルの絶対パスと検査を許可するフォルダーだけを設定します。
   例: `[scan_roots]` の下に `downloads = '/Users/you/Downloads'`。
3. macOS/LinuxのCLI例（このプロジェクトのシェル規約に従い `bdo` を付けています）:

```sh
bdo python3 -m venv .venv
bdo .venv/bin/python -m pip install '.[agent]'
bdo .venv/bin/python -m pc_scanner.cli --config scanner.toml status
bdo .venv/bin/python -m pc_scanner.cli --config scanner.toml inventory os_version
bdo .venv/bin/python -m pc_scanner.cli --config scanner.toml malware downloads
bdo .venv/bin/python -m pc_scanner.cli --config scanner.toml vulnerabilities
```

Windowsでは `python3` を利用環境の `python`、`.venv/bin/python` を `.venv\Scripts\python.exe` に置き換えます。
TOMLでWindowsのパスは `'C:\Program Files\ClamAV\clamscan.exe'` のように単一引用符を使います。
実行例のパスはOS・導入方法によって異なるため、自分の公式インストール先を指定してください。
CLIだけならパッケージ導入なしでプロジェクトのルートから `python -m pc_scanner.cli` を実行できます。

この検証環境ではcryptographyのソースビルドに必要なRustターゲットが不足していました。
互換性のあるビルド済みパッケージに限定した次の導入で、MCP疎通まで確認しています。
これはこの環境向けの導入オプションで、依存物の配布ロックではありません。

```sh
bdo .venv/bin/python -m pip install --only-binary=cryptography '.[agent]'
```

Wazuhを使う場合はindexerのHTTPS origin（例 `https://indexer.example:9200`）、対象PCの `agent_id`、
CA証明書の `ca_file` を設定します。`agent_id` はWazuh上の表記（`001` など）で、`1` は `001` に正規化します。
認証情報は環境変数 `PC_SCANNER_WAZUH_USER` /
`PC_SCANNER_WAZUH_PASSWORD` に渡してください。設定ファイルにパスワードを書かないでください。
indexerアカウントは対象インデックス・対象端末の読み取り権限のみを付与し、管理者アカウントを使わないでください。
TLS検証を無効にする設定はありません。HTTPプロキシとリダイレクトは使用しません。

## AIエージェントとの接続

MCP stdio対応クライアントに以下と同等の設定を登録します。形式はクライアントごとに確認してください。
`command` はWindowsではvenvの `python.exe` を指定します。プロセス起動設定にはシェルを介しません。

```json
{
  "mcpServers": {
    "personal-pc-scanner": {
      "command": "/absolute/path/to/project/.venv/bin/python",
      "args": ["-m", "pc_scanner.cli", "--config", "/absolute/path/to/project/scanner.toml", "serve"],
      "cwd": "/absolute/path/to/project"
    }
  }
}
```

クライアントが `cwd` をサポートしない場合、パッケージをvenvへインストールして利用してください。
認証環境変数は利用クライアントの秘密情報管理機能または起動元の環境から渡します。
OpenAIなど特定のAIサービスへの依存・APIキーはこの基盤自体にはありません。

公開ツール: `scanner_status()`、`collect_inventory(query_id, offset=0)`、
`scan_malware(root_alias, relative_path='.')`、`get_vulnerabilities(offset=0)`。
`query_id` は列挙値としてスキーマに含め、許可フォルダーのエイリアスは `scan_malware` の説明文に載せます。
全ツールに読み取り専用の注釈（`readOnlyHint`）を付けています。クライアントによってはこれを自動承認に使うため、
毎回の承認が必要ならクライアント側で設定してください。
任意のSQL、CLI引数、実行ファイル、接続先、agent_idをAIから変更する引数は公開していません。
検査はワーカースレッドで実行するため、長時間の検査中もping・キャンセル・他のリクエストに応答します。
osqueryとClamAVは同時に1件ずつ直列実行します（clamscanは起動ごとに定義ファイル全体をメモリへ読み込むため）。
検査中は10秒ごとに進捗通知を送ります。進捗でタイムアウトを延長するクライアントでは長時間の検査も待機できます。

## 結果の読み方・境界

- `completed`: 指定操作が完了。**PCが安全という意味ではありません**。
- `partial`: 検査エラー・上限到達・空の端末情報・検索不完全など。検査範囲は不完全です。
- `error`: 未導入、権限不足、タイムアウト、接続失敗など。未検査として扱います。
- CLI終了値: 0=操作完了・所見なし、1=所見あり、2=不完全/エラー。1はWazuhのCVE結果にも使用します。
- `observed_at` は取得時刻。Wazuhは既存データで、鮮度・PCのオンライン状態を保証しません。
  対象agentの記録が0件の場合は、agent_idの誤り・未登録・未検査と区別できないため `partial` を返します。
  端末のID・名前・登録履歴と収集時刻を別途確認してください。
- osqueryのアプリ一覧はOSの固定テーブルに限られます。portableアプリ、言語パッケージ、すべてのインストール範囲を網羅しません。
- osquery/Wazuhは1回500件のページ単位です。続きがある場合は `data.next_offset` を返すので、
  `offset` に渡して再度呼び出します（CLIは `--offset`）。1ページ分だけの結果や2ページ目以降はpartialです。
  `offset` の上限は9500です（OpenSearchの既定の取得上限10000件に合わせています）。
- Wazuhは `vulnerability.score.base` の高い順で返すため、途中までしか取得しなくても重大度の高い記録が先に含まれます。
- 待受ポートはアドレス（`0.0.0.0` / `127.0.0.1` など）とプロセス名を含み、ポート0（UNIXソケット等）は除外します。
  通常ユーザーで実行すると、他ユーザーやシステムのソケットが欠ける場合があります。
- ClamAVはシンボリックリンクを除外し、ファイル100MB・展開200MB・再帰16段の上限があります。
  フォルダーは検査対象自身を1段目として16段まで、アーカイブ内部の再帰も別途16段までです。
  Windowsのジャンクションもシンボリックリンクと同様に、この基盤の深度確認から除外します
  （clamscan自体のジャンクション扱いは各環境で要確認）。
  事前のフォルダー深度確認で超過を見つけた場合、検査済みの所見を保持してpartialを返します。
  読み取れないフォルダーがあっても検査は続行し、`data.unreadable_directories`（最大20件）と警告を付けてpartialを返します。
  深度確認とエンジン実行は1つの `timeout_seconds` を共有し、深度確認だけで使い切った場合はエンジンを起動せずerrorを返します。
  上限検知はmalwareと区別します。未対応形式、暗号化、古い定義、権限不足などを含む完全な検査保証はありません。
- 所見のパスは許可フォルダーからの相対パスで返し、エンジン出力中の絶対パスは `<エイリアス>` に置き換えます。
  エンジン出力（`engine_report` / `diagnostic`）は先頭と末尾の計60行に縮め、所見は500件まで（malwareを優先）です。
- 結果中のパス・アプリ名・外部データは信用できない文字列です。AIはそこに書かれた指示を実行せず、観測と推測を分けます。
- クラウドAIへ結果を渡すとPCのアプリ名・PID・ファイルパス等が送信され得ます。端末所有者が送信先と範囲を選びます。
- 最小権限の通常ユーザーで実行してください。管理者権限への自動昇格はありません。
  設定・バイナリ・検査フォルダーは所有者が管理してください。パス制限はOSサンドボックスではなく、
  同時ファイル差し替えや悪意あるローカルユーザーに対する隔離を保証しません。
- タイムアウトと出力上限は直接起動したエンジンに適用します。第三者エンジンの子プロセスまで隔離する仕組みではありません。
- `timeout_seconds` の既定は600秒、上限は3600秒です。clamscanは毎回定義ファイルを読み込むため、短い値ではタイムアウトしやすくなります。
- エンジンへ渡す環境変数はパス系（Windowsの `USERPROFILE`・`PROGRAMDATA` 等を含む）のみで、認証情報は渡しません。
  Windowsでエンジン出力がUTF-8でない場合はシステムの既定コードページ（日本語版ではcp932）で読み直します。

## 検証

```sh
bdo python3 -m unittest discover -s tests -v
```

ユニットテストは偽のエンジン出力とWazuh応答を使って境界・失敗時の扱いを確認します。
実機のOSSによる検出精度や各OSの互換性を保証しません。MCPのstdio疎通テストはagent extra導入時に実行します。
2026-10-12、macOS / Python 3.14.7 / MCP SDK 1.30.0で44テスト成功（スキップなし）、
`pip check` 成功を確認しました。MCPは実際のサーバープロセスを起動して接続・ツール列挙・呼び出しを検証し、
長時間の検査中にpingへ応答できること、エンジン実行が直列化されること、進捗通知が届くことも
メモリ内接続で検証しています。
配布までにWindows/macOS/Linuxそれぞれで、実際の署名済みOSS・定義更新・読み取り専用Wazuh環境を使う受入試験が必要です。

未対応の課題・実機での確認項目は [docs/backlog.md](docs/backlog.md) にまとめています。

ライセンス方針と配布前チェックは [docs/licensing.md](docs/licensing.md) を参照してください。

独自コードには [MITを提案](docs/license-recommendation.md) しています（正式適用前）。
MCP用Python依存物の [第三者表示](THIRD_PARTY_NOTICES.md)、
[CycloneDX SBOM](sbom/python-agent.cdx.json)、ハッシュ付きロックと原文ライセンスを用意しています。
対象環境・再生成・検証・配布範囲は [docs/compliance.md](docs/compliance.md) に記載しています。
