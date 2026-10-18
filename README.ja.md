# Personal Device Scanner MCP

[![CI](https://github.com/tedorigawa001/PersonalDeviceScanner-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/tedorigawa001/PersonalDeviceScanner-MCP/actions/workflows/ci.yml)

[English](README.md) | **日本語**

自分の PC（Windows / macOS / Linux）と Android 端末の状態を、AIエージェントから**読み取り専用で**確認するための MCP サーバーです。
定評のあるオープンソースの検査ツール（osquery・ClamAV・Wazuh・adb）を呼び出し、結果を AI が扱いやすい JSON で返します。

旧名は *Personal PC Scanner MCP* です。npm パッケージは `personal-device-scanner-mcp` になりました。旧パッケージ
`personal-pc-scanner-mcp` は 2026-10-15 に npm から削除したため、使っている設定は書き換えてください。
旧リポジトリ名へのリンクは新しい名前に転送されます。

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
- USB でつないだ自分の Android 端末を、既知の監視アプリ（ストーカーウェア）や強い権限を持つアプリの観点で点検する（ADB）
- 上記を AI エージェントの MCP ツール、またはコマンドライン（CLI）から実行する

**しないこと**

- ファイルの削除・隔離・修復などの変更（すべて読み取り専用です）
- リアルタイム保護、自動隔離、EDR としての機能
- 独自のソフトウェア名と CVE の照合
- 検査エンジンや定義ファイルの同梱・更新（それぞれ公式配布元から導入・更新してください。エンジンが古くなっていれば
  知らせることはできます。[エンジンの更新を確かめる場合](#エンジンの更新を確かめる場合)）

使いたいエンジンだけを設定すれば動きます。たとえば Wazuh なしで osquery と ClamAV だけを使うこともできます。

## 仕組み

```text
AIクライアント（Claude Desktop など）
   │  MCP（stdio。ネットワークに待受ポートは開きません）
   ▼
Personal Device Scanner（このプロジェクト）
   ├─ osqueryi ……………… OS・アプリ・待受ポートの一覧
   ├─ clamscan ……………… 許可したフォルダーのマルウェア検査
   ├─ Wazuh indexer ……… 登録済み端末の既存の脆弱性情報（HTTPS）
   └─ adb …………………… USB でつないだ登録済みの Android 端末
```

AI が指定できるのは「どの固定クエリを使うか」「どの許可フォルダーを検査するか」だけです。
任意の SQL・任意のパス・実行ファイル・接続先は、AI から変更できません。

## 提供する機能

| MCPツール | CLIコマンド | 使うエンジン | 内容 |
|---|---|---|---|
| `scanner_status()` | `status` | なし | 設定の有無を表示します。エンジンの動作や安全性は確認しません |
| `collect_inventory(query_id, offset=0)` | `inventory <query_id> [--offset N]` | osqueryi | `os_version`・`applications`・`listening_ports` のいずれかを取得します |
| `scan_malware(root_alias, relative_path=".")` | `malware <root_alias> [relative_path]` | clamscan | 許可フォルダー（またはその中のパス）を検査します |
| `get_vulnerabilities(cursor="")` | `vulnerabilities [--cursor C]` | Wazuh indexer | 設定した1台の端末の脆弱性を、深刻度の高い順に取得します |
| `collect_android(device_alias, query_id)` | `android <device_alias> <query_id>` | adb | 登録した Android 端末の `device`（バージョン・セキュリティパッチ）・`apps`（アプリと記録された導入元）・`privileged_access`（ユーザー補助・通知へのアクセス・端末管理）のいずれかを取得します |
| `check_android_monitoring_apps(device_alias)` | `android-check <device_alias>` | adb | 全パッケージを既知の監視アプリと照合し、確認を勧めるアプリを挙げます |
| `check_router(router_alias)` | `router-check <router_alias>` | MyJVN API・KEV のファイル | 登録した家庭用ルーターを、ルーターにアクセスせずに点検します。機種とバージョンを公表された脆弱性と、確かめた設定を公的な推奨と照らし合わせます |
| — | `router-products <maker> <keyword>` | MyJVN API | メーカーの機種と JVN の CPE 名を一覧にします（`jvn_cpes` を選ぶため） |
| — | `history [--limit N] [--json]` | — | この PC に記録したスキャンの要約を表示します（[スキャン履歴](#スキャン履歴)を参照）。AI からは読めません |
| — | `dashboard [--limit N] [--no-open]` | — | スキャン履歴（と、残した詳細）を HTML のページとしてこの PC に書き出し、ブラウザーで開きます（[ダッシュボード](#ダッシュボード)を参照）。AI からは読めません |
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
- **代わりに `npx` で起動する場合**：Python に加えて Node.js 22 以上（[npx で使う場合](#npx-で使う場合npm)を参照）
- **Android を点検する場合**：[Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools)（adb。
  37.0.1 以上で動作を確認）と、Android 10 以上の端末（[Android 端末を使う場合](#android-端末を使う場合)を参照）

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
- 綴りを間違えた `[scan_root]` のような知らない設定は無視されますが、すべての結果の `warnings`
  （MCP サーバーでは起動時のログにも）に「did you mean 'scan_roots'?」のような候補つきで表示されます。

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
    "personal-device-scanner": {
      "command": "/absolute/path/to/project/.venv/bin/python",
      "args": ["-m", "pc_scanner.cli", "--config", "/absolute/path/to/project/scanner.toml", "serve"]
    }
  }
}
```

- Windows では `command` を `C:\\path\\to\\project\\.venv\\Scripts\\python.exe` のようにします（JSON では `\` を `\\` と書きます）。
- 手順2でパッケージを導入済みなので、作業フォルダー（`cwd`）の指定は不要です。
- この基盤自体は、特定の AI サービスの API キーを必要としません。

### npx で使う場合（npm）

手順2と5の代わりに、`npx` で起動することもできます。Python 3.11 以上は引き続き必要です。
npm パッケージに入っているのは、小さな起動用スクリプト・このプロジェクトの Python コード・ロックファイルだけで、第三者のコードは含みません。

```json
{
  "mcpServers": {
    "personal-device-scanner": {
      "command": "npx",
      "args": ["-y", "personal-device-scanner-mcp@0.6.0", "--config", "/absolute/path/to/scanner.toml", "serve"]
    }
  }
}
```

- 初回の起動時に、キャッシュフォルダーへ専用の仮想環境を作り、Python のパッケージを導入します
  （macOS：`~/Library/Caches/personal-device-scanner-mcp`、Linux：`~/.cache/personal-device-scanner-mcp`、
  Windows：`%LOCALAPPDATA%\personal-device-scanner-mcp`）。クライアントがサーバーの起動を待つ時間より長くかかることがあるため、
  先に一度 `npx -y personal-device-scanner-mcp@0.6.0 setup` を実行してください。
- Windows x64・macOS（Intel / Apple シリコン）・Linux x86_64 の CPython 3.14 では、同梱のロックファイルのハッシュで
  検証して導入します（`pip --require-hashes`）。それ以外の Python や CPU では、同じバージョンをハッシュの検証なしで導入し、
  その旨を stderr に表示します。起動用スクリプトと pip の出力はすべて stderr に出し、MCP の通信路には混ぜません。
- Python は `python3.14`、`python3.13` … `python3`（Windows は `py -3.14`、`py -3`、`python`）の順に、`PATH` の
  絶対パスのフォルダーからだけ探します。現在のフォルダー（Windows は本来ここを最初に探します）や、`.` のような相対の `PATH` は
  見ないため、ダウンロードフォルダーなどに置かれた Python と同じ名前のプログラムは実行されません。
  指定する場合は `PC_SCANNER_PYTHON` に絶対パスを設定します。`PC_SCANNER_CACHE_DIR`（絶対パス）でキャッシュの場所を変えられます。
- 更新を自分で判断できるよう、バージョンは固定（`@0.6.0`）してください。バージョンと Python ごとに別の環境を作るので、
  キャッシュフォルダー内の古い環境（`<バージョン>-<ハッシュ>` のような名前のフォルダー）は削除してかまいません。フォルダーごとは削除しないでください。
  Windows では、同じフォルダーにスキャン履歴も入っています。
- CLI も同じように使えます。例：`npx -y personal-device-scanner-mcp@0.6.0 --config scanner.toml status`
- Windows のクライアントが `npx` を直接起動できない場合は、`"command": "cmd"`、`"args": ["/c", "npx", ...]` とします。

### Wazuh を使う場合

`scanner.toml` の `[wazuh]` に次を設定します。

```toml
[wazuh]
url = 'https://indexer.example:9200'   # indexer の HTTPS アドレス（管理 API のポート 55000 ではありません）
agent_id = '001'                        # Wazuh 上の端末 ID。'1' と書いても '001' として扱います
ca_file = '/path/to/root-ca.pem'        # indexer の CA 証明書
agent_name = ''                         # 任意。Wazuh 上のエージェント名がこの PC のホスト名と違う場合に指定
```

ユーザー名とパスワードは**設定ファイルに書かず**、環境変数で渡します。

```sh
export PC_SCANNER_WAZUH_USER='reader'
export PC_SCANNER_WAZUH_PASSWORD='...'
```

MCP で使う場合は、クライアントの秘密情報管理機能や起動元の環境から渡してください。
indexer のアカウントには、対象端末の脆弱性インデックスへの**読み取り権限だけ**を付与し、管理者アカウントは使わないでください。

### Android 端末を使う場合

USB ケーブルでこの PC につないだ**自分の** Android スマートフォン・タブレットを点検します。読み取るだけで、
端末にアプリを入れたり、消したり、設定を変えたりはしません。設計は [docs/android-design.md](docs/android-design.md) にあります。

1. Google の [Android SDK Platform-Tools](https://developer.android.com/tools/releases/platform-tools) を導入します。
2. 端末で開発者向けオプションと **USB デバッグ**を有効にし、ケーブルでつないで、端末に表示されるこの PC を承認します。
3. `adb devices -l` で端末のシリアルを確認します。
4. 監視アプリの指標（Echap の [stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators)、CC-BY 4.0）を
   ダウンロードします。ClamAV の定義ファイルと同じように定期的に更新してください。このツール自身はダウンロードしません。

   ```sh
   curl -fsSL -o /absolute/path/to/stalkerware.stix2 https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/stalkerware.stix2
   ```

   Windows では `curl.exe` を同じ引数で使います。
5. 設定を追加します。

   ```toml
   [android]
   adb_binary = '/absolute/path/to/platform-tools/adb'
   indicators_file = '/absolute/path/to/stalkerware.stix2'

   [android_devices]
   # 「エイリアス = シリアル」。AI はエイリアスでしか端末を指定できません
   my-phone = 'SERIAL'
   ```

6. 点検します：`.venv/bin/python -m pc_scanner.cli --config scanner.toml android-check my-phone`
7. **終わったら USB デバッグを無効にし**、開発者向けオプションの「USB デバッグの承認を取り消す」を行ってください。
   USB デバッグは端末の攻撃面を広げます。

- 点検するのは USB 接続の端末だけです。接続方式はシリアルから推測せず、adb の報告（`adb track-devices --proto-text`）で
  確かめるため、ワイヤレスデバッグやエミュレーターは対象外になります。
- adb は初回にサーバー（localhost:5037）を起動し、動かしたままにします。Android Studio などと共有されるため、このツールからは
  止めません。止めたいときは `adb kill-server` を実行します。

### 家庭用ルーターを使う場合

**自分の**家庭用 Wi-Fi ルーターを、**ルーターに一切アクセスせずに**点検します。ルーターへの通信・ログイン・スキャンは行いません。
メーカー・機種・ファームウェアのバージョンと、管理画面で見た設定を書くと、公表された脆弱性と公的な推奨に照らし合わせます。
設計は [docs/router-design.md](docs/router-design.md) にあります。

1. 管理画面で機種とファームウェアのバージョンを確かめ、メーカーのサポートが続いているかを確かめます
   （各メーカーのサポート終了一覧は [NOTICE](https://notice.go.jp/end_of_support) から辿れます）。
2. 任意（**JVN iPedia** の脆弱性）：`router.jvn_lookup` を有効にします。点検のたびに、機種の CPE 名（それ以外は送りません）を
   IPA の MyJVN API に HTTPS で送ります。結果には「出典：MyJVN API（IPA）」を表示します。機種の CPE 名を調べ
   （バッファロー・NEC・アイ・オー・データ・エレコム）、当てはまるものを `jvn_cpes` に写します。

   ```sh
   .venv/bin/python -m pc_scanner.cli --config scanner.toml router-products buffalo WSR-3200
   ```

3. 任意（**悪用が確認された**脆弱性）：CISA KEV（CC0）を自分でダウンロードし、定期的に更新します。このツールはダウンロードしません。
   載っているのは主に海外メーカー（D-Link・TP-Link・Zyxel・NETGEAR・ASUS など）です。

   ```sh
   curl -fsSL -o /absolute/path/to/kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
   ```

4. 設定を書きます。自分で確かめたものだけを書き、確かめていない項目は書かずにおくと「未確認」と表示されます。

   ```toml
   [router]
   jvn_lookup = true
   kev_file = '/absolute/path/to/kev.json'

   [routers.home]                  # 「home」は AI が使うエイリアス
   maker = "buffalo"               # buffalo・nec・iodata・elecom、またはメーカー名
   model = "WSR-3200AX4S"
   firmware = "1.42"               # 管理画面の表示のまま
   jvn_cpes = ["cpe:/h:buffalo_inc:wsr-3200ax4s"]
   support = "supported"           # supported・ended・unknown
   checked_on = 2026-10-17         # 下の設定を確かめた日

   [routers.home.settings]
   auto_update = true
   admin_password_changed = true
   remote_admin = false
   vpn_server = false
   ddns = false
   upnp = false
   wps = false
   wifi_security = "wpa3"          # wpa3・wpa2-aes・wpa2-tkip・wep・open
   unknown_vpn_accounts = false
   ```

5. 確認：`.venv/bin/python -m pc_scanner.cli --config scanner.toml router-check home`

- ルーターのパスワードは書かないでください。パスワードらしいキーがあると、削除を促す警告を出します。
- 結果が `completed` になるのは、JVN と KEV の両方を全件照合でき、設定がすべて回答済みで、確かめた日が新しい
  （`router.max_check_age_days`、既定180日）ときだけです。

### エンジンの更新を確かめる場合

このツールがエンジンを更新することはありませんが、古くなっていれば知らせることはできます。設定ファイルで有効にします。

```toml
[updates]
lookup = true    # エンジンのバージョンを公式の最新リリースと比べる
```

有効にすると、インベントリ・マルウェア検査・Android の点検のたびに、使ったエンジンのバージョン（`osqueryi --version`・
`clamscan --version`・`adb version`）を読み、最新のリリースと比べます。

| エンジン | 比べる相手 | 更新の入手先 |
|---|---|---|
| osquery | GitHub で公開された最新のリリース（プレリリースは除く） | https://osquery.io/downloads/ |
| ClamAV | GitHub の、同じ系列（1.4、1.5 など）の最新のリリース | https://docs.clamav.net/manual/Installing.html |
| adb | Google の Android SDK リポジトリにある安定版の Platform-Tools | https://developer.android.com/tools/releases/platform-tools |

- 古いエンジンには、最新のバージョンと入手先を書いた警告が付きます。結果の `status` は変わりません。
  詳しくは `data.engine_update` の `installed`・`latest`・`status`（`current`・`outdated`・`newer`・`unknown`）・
  `checked_at` にあります。
- ClamAV は複数の系列を並行して保守し、同じ日にそろって修正版を出します。直近のそうした更新から外れた系列や、
  最新10件のリリースにない系列は、サポートが終わった可能性があると報告します。
- 調べた結果は、スキャン履歴の隣に履歴の名前を元にした名前（既定は `history.jsonl.releases`）で1日保存するので、
  ほとんどのスキャンは通信しません。
  取得に失敗したときは1時間後にやり直し、それまでは30日以内の情報を、その日付とともに使います。
- 接続先は `api.github.com` と `dl.google.com` だけで、HTTPS（証明書を検証、プロキシとリダイレクトは使わない）です。
  比較はこの PC の中で行い、PC の情報は送りませんが、接続先には IP アドレスが伝わります。GitHub は、サインインしない要求を
  1つの IP アドレスにつき1時間60回までに制限しています。
- 有効にすると、スキャンのツールはインターネットに接続するものとして示します（`openWorldHint`）。Wazuh とルーターの点検には、
  この PC 上に比べるエンジンがありません。

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
| `local.max_signature_age_days` | ClamAV の定義がこの日数（1〜365）より古いと、検査結果を `partial` にします | `7` |
| `scan_roots.<エイリアス>` | 検査を許可するフォルダー（絶対パス）。エイリアスは英数字・`_`・`-` で64文字まで | なし |
| `wazuh.url` | Wazuh indexer の HTTPS アドレス。空欄なら無効 | 空欄 |
| `wazuh.agent_id` | 対象端末の数字の ID | 空欄 |
| `wazuh.ca_file` | indexer の CA 証明書（PEM 形式）の絶対パス。空欄ならシステムの証明書を使います。ファイルがなければ読み込み時に警告し、読めない・PEM でない場合は接続前にエラーにします | 空欄 |
| `wazuh.agent_name` | Wazuh 上で期待するエージェント名（大文字小文字を除き完全一致）。空欄ならこの PC のホスト名とドメイン部分を除いて照合します | 空欄 |
| 環境変数 `PC_SCANNER_WAZUH_USER` / `PC_SCANNER_WAZUH_PASSWORD` | Wazuh の認証情報 | — |
| `android.adb_binary` | adb（Android SDK Platform-Tools）の絶対パス。空欄なら Android は無効 | 空欄 |
| `android.indicators_file` | 監視アプリの指標（STIX2）の絶対パス。空欄なら照合せず、点検は `partial` | 空欄 |
| `android.max_indicator_age_days` | 指標が提供元の生成日時からこの日数（1〜365）より古いと、点検は `partial` | `30` |
| `android.max_patch_age_days` | セキュリティパッチがこの日数（1〜3650）より古いと `outdated_patch` として報告 | `90` |
| `android_devices.<エイリアス>` | 点検を許可する Android 端末の adb のシリアル。エイリアスの規則は `scan_roots` と同じ | なし |
| `router.jvn_lookup` | 登録した機種を MyJVN API で JVN iPedia に照会します（CPE 名を IPA に送ります） | `false` |
| `router.kev_file` | ダウンロードした CISA KEV（JSON）の絶対パス。空欄なら照合せず、点検は `partial` | 空欄 |
| `router.max_kev_age_days` | KEV がリリース日時からこの日数（1〜365）より古いと、点検は `partial` | `30` |
| `router.max_check_age_days` | 設定を確かめた日がこの日数（1〜3650）より前だと、点検は `partial` | `180` |
| `routers.<エイリアス>` | 家庭用ルーター：`maker`・`model`・`firmware`・`jvn_cpes`・`support`・`checked_on` と、確かめた `settings`（[家庭用ルーターを使う場合](#家庭用ルーターを使う場合)を参照）。エイリアスの規則は `scan_roots` と同じ | なし |
| `history.enabled` | スキャンごとの要約をこの PC に記録します。`false` で記録しません | `true` |
| `history.file` | 履歴ファイルの絶対パス。空欄ならユーザーごとのフォルダー（[スキャン履歴](#スキャン履歴)を参照） | 空欄 |
| `history.details` | ダッシュボード用に、スキャンごとの結果全体（所見・警告・データ）も残します。有効にする前に[ダッシュボード](#ダッシュボード)を読んでください | `false` |
| `history.details_max_mb` | 残す結果の大きさの上限（1〜1024 MiB）。古いものから削除します | `50` |
| `updates.lookup` | スキャンのたびに、osquery・ClamAV・adb のバージョンを公式の最新リリースと比べます（GitHub と Google に接続します。[エンジンの更新を確かめる場合](#エンジンの更新を確かめる場合)） | `false` |

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
| `partial` | 一部しか確認できていません（読めないフォルダー、上限到達、古い定義ファイル、結果が0件、ページの途中など） | `warnings` を確認してください。検査範囲は不完全です |
| `error` | 実行できませんでした（未設定、権限不足、タイムアウト、接続失敗など） | 未検査として扱ってください |

### CLI の終了コード

| 終了コード | 意味 |
|---|---|
| `0` | 完了し、所見なし |
| `1` | 完了し、所見あり（マルウェア・脆弱性など） |
| `2` | `partial` または `error`（想定外の内部エラーも JSON で返します）。**所見があっても `partial` なら 2 になります** |

### 件数が多いとき（ページング）

インベントリと Wazuh の結果は、1回500件ずつ返します。1ページ分だけの結果や、2ページ目以降は `partial` になります。

- **インベントリ**：続きがあると `data.next_offset` に数値が入ります。その値を `offset`（CLI では `--offset`）に渡します。
  `offset` の上限は 9500 です。
- **Wazuh**：続きがあると `data.next_cursor` に文字列が入ります。その値を変えずに `cursor`（CLI では `--cursor`）に渡します。
  上限はなく、1万件を超える結果も取得できます。各ページは前のページの最後の記録の続きから始まり、深刻度、CVE、
  Wazuh がパッケージを識別する項目の順に並べるため、ページの境目で記録が抜けたり重複したりしません。
  取得の途中で Wazuh のデータが更新されると、ページ間で記録がずれることがあります。カーソルにページ番号を含めるようにしたため、
  0.3.0 のカーソルは受け付けません。先頭のページから取得し直してください。

### スキャン履歴

CLI から実行したスキャンと、AI が MCP で実行したスキャンを、1回につき1行の要約としてこの PC に記録します。
`status` と `history` は記録しません。

```sh
.venv/bin/python -m pc_scanner.cli --config scanner.toml history
```

```text
TIME                 VIA  OPERATION      STATUS     FINDINGS    SECONDS  TARGET
2026-10-15 09:12:04  mcp  malware        completed  0              41.8  downloads
2026-10-15 09:13:30  cli  android_check  partial    1 (high 1)      6.2  phone
2026-10-15 09:20:11  mcp  inventory      error      -               0.0  applications
                     error: osquery_binary is not configured or not installed
```

- **記録する内容**：開始時刻、`cli` か `mcp` か、操作と対象（フォルダーのエイリアスと相対パス、`query_id`、端末のエイリアス。
  Wazuh はページ番号と、ページの開始位置の短い一方向の指紋だけで、カーソルは記録しません）、`status`、深刻度ごとの所見の件数、警告の件数、かかった時間、エラーの内容、
  ページに分かれる結果では次のページがあるかどうかです。
  **所見そのもの（ファイル名・シグネチャ名・アプリ名・パッケージ名・CVE）は、`history.details` を有効にしない限り記録しません**
  （[ダッシュボード](#ダッシュボード)を参照）。ページに分かれる結果は1ページを1行とし、そのページの所見を数えます。
- **AI からは読めません**：履歴を読む MCP ツールはなく、所有者がこのコマンドで見るだけです。`--limit N`（1〜1000、既定は20）で
  表示する最新の件数を、`--json` で表の代わりに JSON を出力します。
- **保存場所**：macOS は `~/Library/Application Support/personal-device-scanner-mcp/history.jsonl`、Linux は
  `~/.local/state/personal-device-scanner-mcp/history.jsonl`（`$XDG_STATE_HOME` があればその下）、Windows は
  `%LOCALAPPDATA%\personal-device-scanner-mcp\history.jsonl` です。`history.file` で変えられます。macOS / Linux では
  `.1` を含む履歴のファイルを本人だけが読める状態（0600）に保ちます（既存のファイルの権限が広ければ直します）。
  履歴のファイルは、本人の通常のファイルで別名（ハードリンク）がないこと、ロック用のファイルと詳細のフォルダーは本人のものであることを
  確かめ、そうでないものやリンクには書き込みません。保護はファイルの権限によるもので、macOS ではフォルダーから引き継がれた ACL は
  外さないため、履歴は既定の場所のように本人だけが書き込めるフォルダーに置いてください。
- **大きさ**：ファイルが1 MiB に達すると `history.jsonl.1` に名前を変え（前の `.1` は消えます）、最新の数千件ほどを残します。
  履歴を消すには `history.jsonl` と `history.jsonl.1` を削除します。隣の空の `history.jsonl.lock` は、同時に動く CLI と
  MCP サーバーが順番に書き込むためのもので、ほかのプロセスの履歴を回して上書きしないようにしています。
- **記録をやめる**：`history.enabled = false` にします。それまでの記録は `history` で引き続き表示できます。
- 履歴を書き込めなくてもスキャンには影響せず、結果に警告が付きます。

### ダッシュボード

```sh
.venv/bin/python -m pc_scanner.cli --config scanner.toml dashboard
```

履歴ファイルの隣に `history.html` を書き出し、ブラウザーで開きます（`--no-open` なら書き出すだけ。`--limit N`（1〜1000、既定は100）で
含める最新の件数を指定します）。ページには対象ごとの最新の結果と、すべてのスキャンを新しい順に並べます。スキャンを開くと、
警告・所見・データを確認できます。

- **ページはまとめて数えます**：インベントリと Wazuh では、対象ごとの最新の結果を、最新の先頭ページと、その後に取得した続きのページを
  合わせたものとします。それらのページの所見の合計、最も悪い `status`、ページ数、続きのページが残っているかを表示します。
  続きが残っているかは、最も先のページの結果で判断します。同じページを取り直した場合は、前の取得を置き換えます。インベントリは offset で、
  Wazuh はカーソルに含まれるページ番号で同じページを見分けます。0.3.0 の履歴の行には Wazuh のページ番号がないため、失敗したページは
  カーソルを返さないことを利用し、2ページ目以降で失敗した直後に取得したページを、そのページの取り直しとして扱います。

- **詳細は既定では残しません。** その場合、ページには `history` と同じ要約だけを表示します。所見を見るには `history.details = true` に
  します。それ以降、スキャンごとの結果全体（AI が受け取ったもの）を `history.jsonl.details/` に1スキャン1ファイルで残します。
- **有効にする前によく考えてください。** 詳細にはファイル名・アプリ名・パッケージ名・CVE が含まれます。特に、スマートフォンの監視アプリを
  点検する場合、見つかったことを示す結果は、この PC を使える人なら誰でも見られます。監視アプリを入れた本人も例外ではありません。
- **大きさ**：残した結果が `history.details_max_mb`（既定は50 MiB）を超えると、古いものから削除します。最新のものは必ず残します。
  詳細を残さなかったスキャンや、削除済みのスキャンは、ページにその旨を表示します。
- **安全に開けます**：ページは1つのファイルで、何も読み込まず、スクリプトも動かしません（Content Security Policy で自身のスタイルだけを
  許可）。ファイル名・アプリ名・パッケージ名はすべて文字列として表示します。macOS / Linux では、ページと残した結果を本人だけが
  読めるようにし（0600、フォルダーは 0700）、その場所にあるリンクは使いません。
- **自動では更新しません**：新しくスキャンしたら、もう一度 `dashboard` を実行します。詳細を消すには `history.html` と
  `history.jsonl.details/` を削除します。
- ページと残した結果を読む MCP ツールはなく、AI からは読めません。

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
- iCloud・OneDrive等の未取得ファイル／フォルダーは、macOSのdatalessフラグ・Windowsのoffline／recall属性で判別し、内容を開かずに除外します。
  除外があれば `partial` と警告を返し、`data.cloud_excluded_count` と `data.cloud_excluded_paths`（最大20件）に記録します。
  取得済みのファイルは検査します。除外条件が大きすぎる場合や安全に渡せない場合は検査を開始せず `partial` を返します。
  ClamAV は除外条件をパスの先頭512バイト（UTF-8）としか照合しないため、それより長いパスの未取得ファイルがある場合も、
  ClamAV が読んでダウンロードしてしまわないよう、検査を開始せず `partial` を返します。
  判別は事前確認時点の状態に基づきます。同時に同期状態が変わる場合や、これらの属性を使わないプロバイダーは保証対象外です。
- 読めないフォルダーがあっても検査は続け、`data.unreadable_directories`（最大20件）に記録して `partial` を返します。
- 検出結果は ClamAV 自身の集計と照合します。感染ファイル数やエラー数が読み取った内容と合わない場合や、
  検出が許可フォルダー内の実在するファイルを指していない場合は `partial` とし、その所見には `path` を付けません。
  ClamAV の集計は `data.engine_counts` に入ります。
- ファイル名に改行があると、ある検出が別のファイルのものに見えることがあります。そうした名前が1つでもあれば、
  どの所見にも `path` を付けずに `partial` とし、その名前を（エスケープして）`data.line_break_names` に示します。
- 検査の前に `clamscan --version` で定義ファイルの日付を確認します。`max_signature_age_days`（既定は7日。ClamAV 自身が
  警告を出すのと同じ日数）より古い場合や、日付が分からない場合も検査は行いますが、結果は `partial` になり、
  `freshclam` での更新を促す警告が付きます。エンジンと定義の版、作成日時、経過日数（0.1日単位で切り上げ）は
  `data.signatures` に入ります。
- 未対応の形式、暗号化されたファイル、古い定義ファイルなどでは検出できないことがあります。
- clamscan は毎回定義ファイルを読み込むため、制限時間を短くするとタイムアウトしやすくなります。

### Wazuh

- 取得するのは Wazuh に**すでに保存されている**情報です。インデックスに検査時刻が記録されないため鮮度は確認できず
  （`data.freshness` は `unverified` のまま）、PC が今オンラインかどうかも分かりません。
- Wazuh への要求は全体で約30秒までとし、1件ずつ実行します。キャンセルもできます。
  応答が少しずつ届く場合や途中で止まった場合も、期限やキャンセルから約0.1秒以内に打ち切ります。
- 別の端末の結果を取り違えないよう、インデックス上のエージェント名をこの PC のホスト名（または `wazuh.agent_name`）と
  照合します。一致しない場合や名前が記録されていない場合は、警告を付けて `partial` を返します。
  名前・照合先・Wazuh が記録した OS は `data.device` に入ります。
- 対象端末の記録が0件のときは、端末 ID の誤り・未登録・未検査と区別できないため `partial` を返します。
  端末の ID・名前・登録状況と収集時刻を、Wazuh 側で確認してください。

### Android

- 点検できるのは USB 接続の Android 10 以上の端末です（Android 10 と 16 のエミュレーターで確認）。エミュレーターと
  ワイヤレスデバッグは USB 接続ではないため対象外です。
- 照合できるのは指標ファイルにある監視アプリだけで、パッケージ名で照合します。名前を変えたものや未登録のものは検出できません。
  署名証明書による照合や、MVT のような詳細な検査は行いません。
- `review`（Google Play 以外から入った、または導入元が不明なアプリが、ユーザー補助・通知へのアクセス・端末管理を持つ）は
  確認のきっかけであって、悪意の判定ではありません。端末管理・支援技術・業務用のアプリも該当します。watchware との一致は、
  本人や家族が承知のうえで入れたアプリのこともあります。
- 導入元は端末が記録した値です。`unknown` はサイドロードという意味ではなく、ランチャー活動がないこともアイコンを隠している
  という意味ではありません。
- 仕事用プロファイルを含め、ユーザーごとに調べます。仕事用プロファイルのユーザー補助は親ユーザーと共有されるため、
  親ユーザーのアプリと突き合わせます。
- 読み取れなかった項目は `data.unavailable` に並べて `partial` とし、「該当なし」としては扱いません。
  コマンドが成功しても出力が想定した形でない場合も同じです。端末から何も読み取れなければ `error` になります。
  指標ファイルが壊れていても端末の点検は止めず、`partial` を返します。
- 端末管理アプリが有効なときの `dumpsys device_policy` の形式は AOSP のソースに基づくもので、エミュレーターでは再現できませんでした。
  メーカーによって異なることがあります。
- 返す情報：Android のバージョン、セキュリティパッチ、機種、パッケージ名とバージョン、ユーザー ID。返さない情報：シリアル、
  ユーザー名、アカウント、電話番号、アプリのデータ。
- adb は、この PC のサーバー用のポート（localhost:5037）で応答する相手を信用します。ほかの人もサインインする PC では、
  先に偽の ADB サーバーを起動されると、偽の結果を返されるおそれがあります。自分の PC で使うか、点検の前に自分で
  `adb kill-server` と `adb start-server` を実行してください。

### 家庭用ルーター

- ルーターにはアクセスしないため、結果はすべて書いた内容に基づきます。機種やバージョンが違えば結果も違い、設定は回答のとおりにしか分かりません。
- 照合できるのは公表された脆弱性だけです。国内メーカーは JVN iPedia に多く載り、CISA KEV にはほとんど載っていません。
  所見なしは安全の証明になりません。
- 影響を受けるバージョンは自由記述です。比べるのは自分の機種（CPE で一致したもの）の記述だけで、「Ver.2.55より前」「2.30 およびそれ以前」の
  ような決まった形のときだけです。バージョン番号として比べた結果と小数として比べた結果が食い違う場合（「2.6」と「2.55」など）や、
  形が分からない場合、自分の機種の項目にバージョンの記述がない場合は、記述を添えて `unknown` にします。メーカーの告知で確かめてください。
- KEV にはバージョンがないため、メーカー名と機種名での一致は確認を促すもの（`match: model`）です。機種名は製品名の中に単語として
  そのまま現れる必要があります（「DIR-85」は「DIR-859」に一致しません）。同じメーカーのルーター全般の項目（「Multiple Routers」など）は
  より弱い促し（`match: maker_only`）で、NAS・カメラなどほかの製品の項目は含めません。
- JVN は全期間を検索します（MyJVN API は日付を指定しないと過去1週間だけを検索します）。1回の点検で200件まで、1秒に1回まで要求します。
  取得できなかった分（上限・期限切れ・エラー・ページの食い違い）があれば、件数と理由を添えて `partial` にし、「該当しない」とは数えません。
- JVN が登録していない CPE 名は「脆弱性なし」とせず、その旨を報告します（JVN の製品一覧で確認）。バッファロー・NEC・
  アイ・オー・データ・エレコムでは、ほかのメーカーの CPE 名を設定の読み込み時に警告します。
- JVN は 2027 年に新しい API（JSON・CPE 2.3・バージョンでの絞り込み）に移る予定で、そのときに移行します。

### プライバシー

- クラウドの AI に結果を渡すと、アプリ名・プロセス ID・ファイル名・ホスト名などが送信されることがあります。送信先と範囲は PC の所有者が決めてください。
- 送信量を減らすため、ファイルのパスは許可フォルダーからの相対パスで返し、エンジン出力中の絶対パスは `<エイリアス>` に置き換えます。
- PC やインデックスから来る文字列（ファイル名・アプリ名・パッケージ名・エンジン出力）は、返す前に無害化します。
  制御文字・双方向制御文字・ゼロ幅文字は `\uXXXX`、UTF-8 でないバイトは `\xNN` で示し、名前は256文字
  （パスは1,024文字）までに切り詰めます。osquery の行は想定した列だけを残し、Wazuh の項目は型を確認します。
- エンジン出力は先頭と末尾の計60行に縮め、500文字を超える行も前後を残して縮めます（縮めた場合は `data.engine_text_truncated` が true）。所見は500件まで（マルウェアを優先）です。

### 動作上の前提

- 管理者権限ではなく、**通常ユーザー**で実行してください。自動で権限を昇格することはありません。
- フォルダーの制限は OS のサンドボックスではありません。悪意のあるローカルユーザーによるファイルの差し替えなどは防げません。
- タイムアウト・出力上限・キャンセルのときは、エンジンが起動した子プロセスもまとめて停止します
  （macOS / Linux はプロセスグループ、Windows は Job Object）。エンジンが正常に終了した後に残ったプロセスも停止します。
  ただし、自分からグループを抜けたプロセス（macOS / Linux で新しいセッションを始めたものなど）は止められません。
  そのプロセスがエンジンの出力を開いたままにした場合は、エラーになります。
- macOS / Linux では、この基盤が SIGTERM を受けると、実行中のエンジンも止めてから終了します。SIGKILL は捕捉できません。

## 安全のための設計

- **固定の操作だけ**：任意の SQL・パス・実行ファイル・接続先・端末 ID を AI から指定できません。
- **読み取り専用**：ファイルの削除や隔離を行うオプションは使いません。全ツールに読み取り専用の注釈（`readOnlyHint`）を付けています。
  クライアントによってはこの注釈を理由に承認なしで実行するため、毎回承認したい場合はクライアント側で設定してください。
- **シェルを使わない**：エンジンはシェルを介さずに直接起動します。Windows の `.bat` / `.cmd` は起動しません。
  Windows では、検査対象のパスがシステムの文字コードで正確に表せない場合、エンジンを起動する前に拒否します。
  近い文字への置き換え（best-fit）で U+FF02 などが引用符に変わり、オプションを追加されるおそれがあるためです。
- **認証情報を渡さない**：エンジンに渡す環境変数は、パスに関するもの（Windows の `USERPROFILE`・`PROGRAMDATA` など）だけです。
- **通信を限定**：Wazuh への接続は HTTPS のみで、証明書の検証は無効にできません。プロキシとリダイレクトも使いません。
  任意のエンジンの最新リリースの確認も、同じ方法で GitHub と Google にだけ接続し、この PC の情報は送りません。
- **AI の指示を信用しない**：結果に含まれるファイル名やアプリ名は信用できない文字列として扱うよう、AI に指示しています。
- **Android は読み取り専用で接続を固定**：固定の adb コマンドだけを、USB と確認した接続（`adb -t`）に対して実行します。
  端末から読み取った文字列は端末へのコマンドに入れず、入れるのは数字と確認したユーザー ID と転送 ID だけです。
- **ルーターにはアクセスしない**：スキャン・ログイン・パスワードの試行は行いません。通信は任意の MyJVN API（HTTPS・証明書を検証・
  プロキシとリダイレクトを使わない）だけで、送るのは機種の CPE 名です。文書型宣言（DTD）を含む XML は解析する前に拒否します。
- **長時間の検査でも止まらない**：検査は別スレッドで実行し、エンジンは1つずつ順番に動かします。
  検査中は10秒ごとに進捗を通知するので、進捗でタイムアウトを延長するクライアントなら長い検査も待てます。
- **キャンセルで止まる**：AI クライアントが要求をキャンセルすると、実行中のエンジンとその子プロセスを約0.1秒以内に停止します。
  順番待ちの検査は開始されません。
- **履歴はこの PC に**：スキャン履歴には、`history.details` を有効にしない限り所見を記録しません。履歴にもダッシュボードにも
  読み出す MCP ツールはないため、AI は読めません。ダッシュボードのページはスクリプトを動かさず、何も読み込みません。
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
- Android のテスト（`tests/test_android.py`）は、Android 10 と 16 のエミュレーターから得た出力（名前は合成）を使い、
  実際に出力し続けるプロセスでの USB の確認、各出力の解析、指標の鮮度、仕事用プロファイル、読み取れなかった項目の扱いを
  確かめます。同じコードをエミュレーターでも実行しました（[記録](docs/acceptance/android-emulator-2026-10-14.json)）。
- npm の起動用スクリプトには別のテストがあります（Node.js 22 以上）：`node --test npm/test/launcher.test.js npm/test/roundtrip.test.js`。
  `PC_SCANNER_NPM_E2E=1` を設定すると（PyPI からパッケージを導入します）、利用者と同じようにパッケージを作って導入し、
  初回の `serve` で自動的に準備して MCP に応答することを確かめます。あわせて、stdout に MCP のメッセージ以外が出ないこと、
  ロックのハッシュが1つでも違えば準備が止まること、現在のフォルダーに置かれたモジュールを読み込まないこと、
  （macOS / Linux）起動用スクリプトへの SIGTERM でサーバーも止まることを確認します。CI では全 OS × Python 3.11 / 3.14 で実行します。
- 実際のエンジンでの検出精度や、各 OS での動作は保証していません。配布前に、各 OS の実機での受入試験が必要です。

## 関連ドキュメント・ライセンス

- [docs/backlog.md](docs/backlog.md)：未対応の課題と、実機で確認すべき項目
- [docs/licensing.md](docs/licensing.md)：ライセンス方針と配布前チェック
- [docs/compliance.md](docs/compliance.md)：SBOM・第三者表示の対象範囲と再生成手順
- [docs/releasing.md](docs/releasing.md)：npm パッケージのリリース手順（GitHub Actions からのステージド公開）
- [profiles/](profiles/)：Windows・Linux・macOS arm64 向けのロック・SBOM・第三者表示（直下は macOS x86_64 の参照版）
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)・[CycloneDX SBOM](sbom/python-agent.cdx.json)：MCP 用 Python 依存パッケージの表示

独自コードのライセンスは [MIT License](LICENSE)（Copyright (c) 2026 tedorigawa001）です。
選んだ理由は [docs/license-recommendation.md](docs/license-recommendation.md) にあります。第三者のコンポーネントはそれぞれのライセンスのままです。
このリポジトリは Wazuh・osquery・ClamAV のコード、バイナリ、ルール、定義ファイルを含みません。
