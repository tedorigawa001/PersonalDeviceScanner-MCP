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
| `get_scan_progress(scan_id="")` | — | なし | MCPの直近の検査の進捗だけを確認します。キャンセル後も照会できます |
| `check_clamav_signatures()` | `check-clamav-signatures` | clamscan | 定義の版・作成日時・鮮度と更新手順を確認します。更新・検査は実行しません |
| `list_malware_gaps(scan_id, ...)` | `malware-gaps <root_alias> [relative_path] --scan GROUP` | なし | 分割検査の未確認理由と対象IDを一覧にします。MCPは同じサーバーの取得結果だけを読み、名前は返しません |
| `rescan_malware_targets(scan_id, revision, target_ids)` | `malware <root_alias> [relative_path] --retry GROUP --revision N --target ID` | clamscan | IDで選んだ未確認範囲だけを再検査します。元の許可範囲・上限を再確認します |
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
      "args": ["-y", "personal-device-scanner-mcp@0.9.0", "--config", "/absolute/path/to/scanner.toml", "serve"]
    }
  }
}
```

- 初回の起動時に、キャッシュフォルダーへ専用の仮想環境を作り、Python のパッケージを導入します
  （macOS：`~/Library/Caches/personal-device-scanner-mcp`、Linux：`~/.cache/personal-device-scanner-mcp`、
  Windows：`%LOCALAPPDATA%\personal-device-scanner-mcp`）。クライアントがサーバーの起動を待つ時間より長くかかることがあるため、
  先に一度 `npx -y personal-device-scanner-mcp@0.9.0 setup` を実行してください。
- Windows x64・macOS（Intel / Apple シリコン）・Linux x86_64 の CPython 3.14 では、同梱のロックファイルのハッシュで
  検証して導入します（`pip --require-hashes`）。それ以外の Python や CPU では、同じバージョンをハッシュの検証なしで導入し、
  その旨を stderr に表示します。起動用スクリプトと pip の出力はすべて stderr に出し、MCP の通信路には混ぜません。
- Python は `python3.15`、`python3.14`、`python3.13` … `python3`（Windows は `py -3.15`、`py -3.14`、`py -3`、`python`）の順に、`PATH` の
  絶対パスのフォルダーからだけ探します。現在のフォルダー（Windows は本来ここを最初に探します）や、`.` のような相対の `PATH` は
  見ないため、ダウンロードフォルダーなどに置かれた Python と同じ名前のプログラムは実行されません。
  指定する場合は `PC_SCANNER_PYTHON` に絶対パスを設定します。`PC_SCANNER_CACHE_DIR`（絶対パス）でキャッシュの場所を変えられます。
  Python を探すときに Python を導入することはありません（Windows の Python install manager は、まだ何も導入されていないと、
  要求された版を自動で導入するため、これを止めています）。適した Python がなければ、その旨を示して止まります。
- 更新を自分で判断できるよう、バージョンは固定（`@0.9.0`）してください。バージョンと Python ごとに別の環境を作るので、
  キャッシュフォルダー内の古い環境（`<バージョン>-<ハッシュ>` のような名前のフォルダー）は削除してかまいません。フォルダーごとは削除しないでください。
  Windows では、同じフォルダーにスキャン履歴も入っています。
- CLI も同じように使えます。例：`npx -y personal-device-scanner-mcp@0.9.0 --config scanner.toml status`
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

### 家庭LANのデバイスを観測する

`lan-devices`で既存のARP・IPv6近隣キャッシュと、許可したmDNS/DNS-SD広告を読みます。
IPの総当たり、ポートへの接続、ルーターへのログイン、脆弱性検査は行いません。管理・探索を許可できる家庭LANだけを登録してください。

```toml
[lan]
enabled = true
timeout_seconds = 15
max_devices = 256
expose_identifiers_to_mcp = false

[lan_networks.home]
interface = "en0"
local_addresses = ["192.168.10.20"]
cidrs = ["192.168.10.0/24"]
neighbor_cache = true
mdns = false
```

接続名・その接続に期待するIP・許可するオンリンクCIDRは所有者が実環境に合わせて記入します。
Windowsはアダプターの `InterfaceGuid`、Linuxはシステムの `ip` コマンドを使用します。
IPv4プライベート範囲と明示したIPv6のULA・リンクローカルに対応し、グローバルIPv6は対象外です。
知らないネットワーク設定キーはエラーにします。DHCPで期待IPが変わったら設定を更新してください。
同じIP構成の別のWi-Fiは識別できないため、実行場所を確認してください。

```sh
pc-scanner --config scanner.toml lan-devices home
pc-scanner --config scanner.toml lan-devices home --json
pc-scanner --config scanner.toml dashboard
```

`mdns=true`は選択した接続の**リンク全体**への問い合わせを許可します。CIDRは採用する結果を制限しますが、
問い合わせが届く相手は制限できません。全体の1〜30秒の上限内で最大5秒観測します。
接続・IPの変更、上限到達、取消は停止して既取得分を `partial` にし、既定接続・VPN・外部DNSへ切り替えません。
必要なOS機能が使えなければ通信せず失敗します。Windows/Linuxの実LAN受入は未実施です。
受信を検証できなければ `receive_unverified`、OSの権限拒否は `blocked` とし、「応答なし」と断定しません。
受信の確認はIP系統ごとで、IPv4とIPv6を登録した場合、片方の応答でもう片方を確認済みとはしません。
5353番の共有・ファイアウォール・ローカルネットワーク許可の実測は受入が残ります。

MCPの `discover_lan_devices(network_alias)` は、所有者が `lan.expose_identifiers_to_mcp=true` にしたときだけ実行できます。
結果のIP・MAC・申告名・サービスはクライアントからAI提供元へ送られる可能性があります。
外部メーカー照会・エンジン更新照会はせず、進捗は段階・経過時間・件数だけです。Ctrl+C/MCP取消で通信資源を閉じます。
ダッシュボードはLANごとの最新観測とサービスの開閉を独立表示し、IP・広告ポートはリンク化せず、脆弱性の円グラフにも加算しません。
通常履歴は件数・手段・制約コードだけです。機器表には `history.details=true` が必要で、
`history.enabled=false`なら結果を永続保存しません。スリープ中・分離された機器などを見逃し、実際の最終通信時刻は不明です。
詳しくは[設計書・受入計画](docs/lan-discovery-design.md)を参照してください。

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
  最新10件のリリースにない系列は、サポートが終わった可能性があると報告します。テスト版や開発版（`-rc`・`-devel-<日付>`
  など）は、同じ番号のリリースより古いものとして扱います。
- 調べた結果は、スキャン履歴の隣に履歴の名前を元にした名前（既定は `history.jsonl.releases`）で1日保存するので、
  ほとんどのスキャンは通信しません。`history.enabled = false` のときは何も書かず、MCP サーバーは動いている間だけ覚え、
  CLI は実行のたびに調べ直します。
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
  直下のものは **macOS arm64（Apple シリコン）/ CPython 3.14 専用**です。Intel Mac・Linux x86_64・Windows x64 では、
  [profiles/](profiles/) にある同じ OS・CPU のロックを指定します（例：Intel Mac は `profiles/darwin-x86_64-cp314/requirements-agent.lock`）。

  ```sh
  .venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-agent.lock
  .venv/bin/python -m pip install --no-deps .
  ```

### 外向き接続の観測（第1段階）

`pc-scanner --config scanner.toml outbound-connections`（JSONは`--json`）で、このPCのOSが公開する
プロセスと接続先IP/portを時間を区切って観測します。`local.osquery_binary`の設定が必要です。
パケット・通信本文・コマンドラインは取得せず、逆引き・外部照会・遮断・権限昇格は行いません。
接続一覧の定期読み取りなので、受信した接続も含み、開始方向や実送信は不明です。
短命接続や他ユーザーのプロセスを見逃しうるため、0件でも「安全」「通信なし」と判断しません。

```toml
[outbound_connections]
enabled = false
duration_seconds = 10
interval_seconds = 1
max_connections = 2000
expose_identifiers_to_mcp = false
save_details = false
```

観測時間は1..60秒、間隔は1..10秒かつ観測時間以下、統合レコード上限は1..2000です。
MCPの`observe_outbound_connections()`は対象等の引数を取りません。プロセス名・PID・接続先が利用するAIへ
渡りうるため、所有者が`expose_identifiers_to_mcp`を明示的に有効にした場合だけ実行します。
MCPクライアントは結果の大きさを制限するため、MCPにはプロセス別・宛先分類別の件数を先に返し、
接続レコードは`internet_candidate`を先頭に最大100件・64KiBまでとします。省いた件数は`omitted_count`に示し、全件はCLIと保存した詳細で確認します。
進捗には件数と保存状況だけを含め、Ctrl+C・MCP取消では途中の結果と終了状態を保持します。

履歴要約は件数と制約だけです。接続先・プロセス詳細は`history.details=true`かつ`outbound_connections.save_details=true`の場合だけ保存します。
他の検査のために詳細保存を有効にしても、利用したサービスの記録に相当する接続先は保存し始めません。
`history.enabled=false`では保存しません。詳細にも通信本文・エンジンの生出力は残しません。
`pc-scanner dashboard`で最新の観測を脆弱性件数と分けて表示し、プロセス別開閉・ページ内履歴リンクで確認できます。
接続先へのリンクは生成しません。読み取りの出現回数をセッション数・送信回数として数えません。
osqueryの固定列だけを使い、ログ・イベント収集を無効にします。シェルのDBはメモリー内です。
このMacの実CLI・ローカルMCP取得と、隔離したChromeでの表示・開閉・履歴リンクは部分受入済みです。
未接続UDPの正規化は修正し、実CLI・ローカルMCPで`invalid_rows`なし・`completed`を確認しました。
権限差・Windows/Linux実機は残ります。[UDP再受入記録](docs/acceptance/outbound-connections-udp-normalization-2026-10-30.json)を参照してください。
[受入記録](docs/acceptance/outbound-connections-macos-2026-10-30.json)と[設計・検証計画](docs/outbound-connections-design.md)を参照してください。

## 設定項目

| 項目 | 説明 | 既定値 |
|---|---|---|
| `outbound_connections` | 接続観測の許可・観測時間1..60秒・間隔1..10秒・上限1..2000件。MCP提供と詳細保存はそれぞれ明示許可 | 無効 |
| `local.osquery_binary` | osqueryi の絶対パス。空欄なら無効 | 空欄 |
| `local.clamav_binary` | clamscan の絶対パス。空欄なら無効。`.bat` / `.cmd` は使えません | 空欄 |
| `local.timeout_seconds` | 1回の操作の制限時間（1〜3600秒）。ClamAV ではフォルダー確認と検査の合計、Wazuh は最大30秒です | `600` |
| `local.max_output_bytes` | エンジン出力の上限（1024〜8388608 バイト） | `1048576` |
| `local.max_signature_age_days` | ClamAV の定義がこの日数（1〜365）より古いと、検査結果を `partial` にします | `7` |
| `scan_roots.<エイリアス>` | 検査を許可するフォルダー（絶対パス）。エイリアスは英数字・`_`・`-` で64文字まで | なし |
| `wazuh.url` | Wazuh indexer の HTTPS アドレス。空欄なら無効 | 空欄 |
| `wazuh.agent_id` | 対象端末の数字の ID | 空欄 |
| `wazuh.ca_file` | indexer の CA 証明書（PEM 形式）の絶対パス。空欄ならシステムの証明書を使います。ファイルがなければ読み込み時に警告し、読めない・PEM でない場合は接続前にエラーにします。Wazuh の証明書ツールが作る CA には鍵用途（key usage）の拡張がないため、この CA に限り Python 3.13 で加わった厳格な確認を緩めます。証明書の連鎖・有効期間・ホスト名は引き続き検証します | 空欄 |
| `wazuh.agent_name` | Wazuh 上で期待するエージェント名（大文字小文字を除き完全一致）。空欄ならこの PC のホスト名とドメイン部分を除いて照合します | 空欄 |
| `wazuh.freshness.enabled` | Managerの接続状態・OSレコード日時を補足。脆弱性結果の鮮度は未検証のまま | `false` |
| `wazuh.freshness.manager_url` / `ca_file` | ManagerのHTTPS originと任意のCA絶対パス。別のManager認証情報は環境変数だけで指定 | 空欄 |
| `wazuh.freshness.max_keepalive_age_seconds` / `max_os_record_age_seconds` | 各観測値の経過時間の閾値（各1〜604800秒） | `300` / `7200` |
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
TIME                 VIA  OPERATION      SOURCE         STATUS     FINDINGS    SECONDS  TARGET
2026-10-15 09:12:04  mcp  malware        ClamAV         completed  0              41.8  downloads
2026-10-15 09:13:30  cli  android_check  Android (adb)  partial    1 (high 1)      6.2  phone
2026-10-15 09:20:11  mcp  inventory      osquery        error      -               0.0  applications
                     error: osquery_binary is not configured or not installed
```

- **SOURCE** は、そのスキャンを行ったもの（Wazuh・ClamAV・Android（adb）・ルーターの点検（JVN・KEV・設定の回答）・osquery）です。
  操作から決まるので履歴には保存せず、`--json` では各項目に `source` として加えます。
- **記録する内容**：開始時刻、`cli` か `mcp` か、操作と対象（フォルダーのエイリアスと相対パス、`query_id`、端末のエイリアス。
  Wazuh はページ番号と、ページの開始位置の短い一方向の指紋だけで、カーソルは記録しません）、`status`、深刻度ごとの所見の件数、警告の件数、かかった時間、エラーの内容、
  ページに分かれる結果では次のページがあるかどうか、`wazuh.freshness` を有効にした Wazuh では `freshness_evidence` の決まった状態と
  正規化した時刻（Manager の接続先・認証情報・応答そのものは記録しません）です。
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
  外さないため、履歴は既定の場所のように本人だけが書き込めるフォルダーに置いてください。Windows では、これらのファイル（と、
  その隣に置くエンジンの最新リリースの情報）の所有者を、開いたハンドルと実効トークンのユーザー SID で確認します。
  Administrators 所有は昇格中かつトークンの既定の所有者の場合だけ許可し、他者所有・ハードリンク・確認失敗は拒否します。
  所有者確認はフォルダーの ACL の代わりにはならないため、引き続き `%LOCALAPPDATA%` など本人だけが書き込める場所に置いてください。
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

- **所見の概要**：ページの先頭に、対象ごとの最新の結果にある所見を深刻度（critical・high・medium・low・unknown）ごとに円グラフで
  示し、件数と割合を添えます。あわせて、検出したスキャン（Wazuh・ClamAV・Android（adb）・ルーターの点検（JVN・KEV・設定の回答）・
  osquery）ごとの件数と、そのうち `partial` や `error` の結果の数を表にします。履歴が常に残す件数を使うので、`history.details` を
  有効にしなくても表示します。対象ごとの最新の結果の表にも、検出したスキャンを示します。
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

### 大きなフォルダーの分割検査と再開

所有者が `scan_roots.home` などで許可したホームフォルダーは、次のように検査できます。設定の許可範囲は自動で広げません。

```sh
pc-scanner --config scanner.toml malware home --batch
pc-scanner --config scanner.toml malware home --resume
```

- MCPでは `scan_malware(root_alias="home", batch=true)`、再開は同じエイリアス・相対パスで `resume=true` を指定します。
  通常の検査でも、クラウド除外指定の長さが上限を超えた場合は自動で分割検査に切り替えます。
- 最初に直下の対象へ分け、1,000項目を超えるサブツリーや、安全に除外指定を渡せないサブツリーをさらに分割します。
  クラウド未取得項目・リンクを辿らず、分割後も元の検査対象から数えた深さ16段の上限を維持します。
- 中断・時間切れでも、それまでに保存した結果は残ります。1回の呼び出し全体に `local.timeout_seconds` が適用されます。
  再開時は現在の対象一覧とメタデータ（名前・識別情報・サイズ・更新時刻・変更時刻・クラウド属性）を確認し、
  同じエンジン・定義・設定でエンジンが終了した変更のない対象だけを再利用します。変更・追加された対象と、エンジンの未完了・失敗対象は再検査します。
  定義の古さ・クラウド除外・検査上限の警告がある終了済み対象を再利用しても、その警告と `partial` は維持します。
  定義や設定が変わった場合は再検査します。これは同時変更のないスナップショットや、内容の再読み込みを保証する機能ではありません。
- `data.batch` に今回の終了対象数（`finished`）、残った対象数（`pending`）、再利用数（`reused`）を返します。
  所見とエンジン件数を今回の対象から集計し、過去の対象や再利用結果を二重計上しません。
  クラウド除外・権限不足・深さやファイルの制限などがあれば `partial` のままです。
  以前の実行の所見は、その対象を再び検査するまで `"retained": true` を付けて残します。対象を検査できなくなった場合
  （分割できないほど大きい・読めない・エンジンの失敗）も同じで、その対象は未確認として示します。
- **チェックポイントは履歴と別に保存します。** 分割検査は `history.enabled=false`・`history.details=false` でも、
  再開に必要な相対ファイル名・所見を履歴の隣の `malware-checkpoints/` に保存します。通常の履歴要約には追加しません。
  macOS/Linuxではフォルダー0700・ファイル0600、Windowsでも所有者を確認し、ファイルのリンク・FIFO・ハードリンクを再開に使いません。
  読み書きできなければエラーにします。不要な保存状態は、次のローカルCLIで1件ずつ削除できます。
- 同時に動かす分割検査は1件。チェックポイントは最大16件、1件16 MiB、1回最大10,000対象に制限します。
  上限や時間切れで終わらなければ未完了を返します。大きな単一ファイル・アーカイブの途中からは再開できず、その対象は再検査します。
  `--batch` を指定して再実行すると、同じ対象のチェックポイントを最初から作り直します。

### 保存済みチェックポイントの管理（ローカルCLIのみ）

```bash
pc-scanner --config scanner.toml malware-checkpoints list
pc-scanner --config scanner.toml malware-checkpoints list --show-paths --json
pc-scanner --config scanner.toml malware-checkpoints delete CHECKPOINT_ID --revision REVISION_TOKEN
```

同じ最新の一覧から`checkpoint_id`と`revision`を省略せずにコピーします。`revision`は削除用の更新確認値で、
`coverage_revision`とは別です。一括削除・ワイルドカード・強制削除はありません。一覧の後に更新・置換された場合は再取得が必要です。
分割検査と同じプロセス内・プロセス間ロックを使い、検査中は**すべてのチェックポイントの削除を保護**します。
一覧は`scan_running=true`・`deletable=false`となり、削除は待ち続けずに失敗します。
`scan_running`は保守的な使用中表示で、別のチェックポイント管理操作がロックを保持している場合も含みます。

削除するのは選択した所有者の私有・通常・上限内のファイル1件だけです。リンク、ジャンクション・再解析ポイント、
ハードリンク、クラウド未取得、上限超過、他者所有は拒否します。安全に読める所有者の壊れたJSONは明示的に削除でき、枠を空けられます。
検査対象のファイル・スキャン履歴・ほかのチェックポイント・共有ロックは削除しません。
そのチェックポイントの進捗と所見は失われるため、以降は`--resume`なしで新しい分割検査を開始してください。
最後の1件を削除しても空のフォルダーとロックは残ります。エンジンは不要で、履歴記録が無効でも、以前の検査ルートが設定から消えていても管理できます。

一覧はID・保存日時・保存済み対象数を示し、新しい保存状態には保存時点のルート別名と相対対象名も記録します。
相対対象名は`--show-paths`のときだけ表示し、テキスト・JSONとも不可視文字をエスケープします。表示名は削除先の決定や現在の許可確認には使いません。
旧形式では対象名が不明なことがあります（schema 2は検査グループIDで過去の結果と照合可能）。
一覧は最大256項目・合計32 MiB・5秒に制限し、省略・読み取り不可は明示します。`deletable`でもOSの権限や他の読取によって削除できない場合があります。
保存先がなければ作成せず、管理操作をスキャン履歴へ追加しません。既存の保存先では共有ロックを作成・再利用します。
MCPにも`Scanner.invoke`にも、この一覧・削除操作を追加しません。

macOSで合成状態と実CLI・MCPを使って検証し、両Pythonの全520件中513件成功・Windows専用7件skip、npmは両環境で各26件成功しました。
Windowsの新しい削除API・ACLの実機受入は未確認です。[検証記録](docs/acceptance/checkpoint-management-2026-10-31.json)を参照してください。

### 未確認範囲と選択再検査

通常・分割検査の `data.coverage` に、未確認の対象範囲数と理由別件数を返します。対象範囲数はファイル数ではありません。
サイズ・アーカイブ・深さ制限、権限不足、クラウド未取得、時間切れ、取消、未到達、メタデータ取得不能などを区別します。
1範囲に複数理由があるため、理由別件数を足して総数にしません。列挙未完は下限、ファイル数は不明と表示します。
古い定義等の信頼性の制約は `assessment_limits` に分け、未検査ファイル数を推測しません。

対象選択は分割検査で開始します。通常検査だけでは再検査用の名前入りファイルを新たに保存しません。

```bash
pc-scanner --config scanner.toml malware home . --batch
pc-scanner --config scanner.toml malware-gaps home . --scan GROUP
pc-scanner --config scanner.toml malware-gaps home . --scan GROUP --show-paths --json
pc-scanner --config scanner.toml malware home . --retry GROUP --revision N --target ID
```

`GROUP`・`N`・`ID` は結果／一覧のグループID・保存成功版・対象IDへ置き換えます。`--target` は最大100個指定でき、
同じIDは重複排除します。`--retry` と `--batch` / `--resume` は併用できません。元のalias・相対対象も指定します。
CLI一覧は既定で名前を含まず、`--show-paths` の明示指定時だけ相対パスを表示します。`--reason` は一覧の絞り込みだけです。
古い版・別グループ・不明なIDは検査前に拒否します。定義・設定が変わった場合は先に明示的に `--resume` してください。

MCPでは分割結果の `data.progress.scan_id` を使い、`list_malware_gaps(scan_id, reasons=[], cursor="", limit=50)` で
名前を含まない対象ID・理由・検査可否を取得します。1ページ最大100対象、カーソルは版・フィルターに固定されます。
`rescan_malware_targets(scan_id, revision, target_ids)` は選んだIDだけを検査します。
取得済みの結果の対応表をサーバー内に直近32要求・シリアライズ容量合計16 MiBまで保持します。
再起動・追い出しで選択が失効したら、元の `scan_malware(..., resume=true)` で現在の範囲を再確認してください。
これらのMCPツールはCLIの保存データや通常の履歴を任意に読み出す機能ではありません。

未取得項目は、選んでもメタデータだけを再確認し、内容を開かず `partial` と除外理由を維持します。
別途ローカルに取得された後でも、検査成功まで未確認を解消しません。属性取得不能時は内容検査を拒否します。
リンク・祖先・元の深さ上限も再検証し、サイズ／アーカイブ上限を自動で緩めません。
属性確認とエンジンの読取りは原子的ではないため、並行変更の競合という既存の限界は残ります。

再検査は同じ対象の現在の状態を置換し、親子分割・再開・結果の再取得を加算しません。
選択対象だけの状態は `data.attempt`、元の範囲全体の状態は最上位 `status` とcoverageに表示します。
他の未確認範囲があれば、選択対象が完了しても全体は `partial` です。消失した対象も検査済みとは扱いません。
保持した所見には観測時刻と未再確認の印を付け、今回の新規検出と区別します。

通常の要約履歴には名前を増やさず、グループ・版・試行ID、理由別件数・品質だけを追加します。
私有チェックポイントはschema 2で結果と台帳を原子的に保存し、既存の0700/0600・所有者確認・容量上限を維持します。
旧schema 1は再開時に再確認して移行します。保存失敗では前のファイルを保持し、メモリー上の結果を新しい保存成功版とは表示しません。

ダッシュボードはグループの最大の保存成功版を1回だけ集計し、未確認理由と信頼性の制約を所見グラフと分けて表示します。
詳細保存が有効なら、チェックボックスで選んだIDのCLIオプションを表示します。静的ページから検査は起動しません。
表示した `--retry ... --revision ...` と選択した `--target ...` を元のCLIコマンドに付け足して実行してください。
詳細がない場合は要約のみを表示し、対象選択はローカルの `malware-gaps` を使います。
画面は保存時点の状態です。古いグループを後から再試行しても、新しく開始したグループの集計を置き換えません。

設計と未確認事項は[設計書](docs/malware-coverage-design.md)、[検証記録](docs/acceptance/malware-coverage-2026-10-28.json)を参照してください。

### 検査前の定義確認と更新案内

```bash
pc-scanner --config scanner.toml check-clamav-signatures
```

MCPでは引数なしの `check_clamav_signatures()` を呼びます。許可フォルダーの設定は不要です。
設定した `clamscan --version` だけを使い、結果の `data.signature_check` にエンジン版、定義の版・作成日時、
経過日数、上限、確認日時、`freshness` と `update_steps` を返します。対象ファイルを検査せず、更新・外部照会・履歴保存もしません。

- `fresh` は日時が上限以内（期限ちょうども含む）、`stale` は期限超過です。
- `unknown` は定義日時が不明、または未来です。日次定義の日時が読めても、定義全体の完全性やPCの安全性を保証しません。
- `check_failed` は実行ファイルの未設定・起動失敗・有効な応答なし・時間切れ・キャンセルなどです。
  終了コードは `fresh` が0、`stale` / `unknown` / `check_failed` が2です。

`malware` の通常検査・分割・再開でも、長いフォルダー走査の前に同じ確認を行い、CLIのstderrとMCPの進捗通知へ
版・日時・鮮度・更新案内を送ります。MCPではクライアントが進捗通知に対応している必要があります。
最終結果にも `data.signature_check` を残します。これは**検査前**の情報で、各対象の検査直前・分割検査終了時の既存判定も維持します。
古い・日時不明なら制約を残して検査を続け、結果が `completed` でも `partial` にします。確認失敗では検査を開始しません。
単独の確認は最大30秒（設定の検査上限が短ければその値）、検査前の確認は検査全体の時間上限を共有します。

更新は、所有者が設定した公式freshclamの自動更新サービス、または承認済みの設定・権限での `freshclam` 実行を案内します。
clamscanが実際に参照する保存先を更新し、権限不足なら管理者へ依頼してください。所有者・権限を自動で変更せず、
MCPでsudoや管理者パスワードを扱いません。更新後は同じ確認を再実行します。手順は[ClamAV公式文書](https://docs.clamav.net/manual/Usage/SignatureManagement.html)を参照してください。
古い定義によるClamAVの標準エラー警告は、分割検査の再利用も妨げる場合があります。
この機能では更新を実行せず、`update_performed` は常に `false` です。

### 長時間検査の進捗

CLIの `malware` は、通常検査・`--batch`・`--resume` とも進捗をstderrに約1秒間隔で表示し、最後にも状態を表示します。
stdoutは従来どおり結果のJSONだけです。Ctrl+Cを1回押すと中止を要求し、エンジンの停止後に保存状況を含む結果を返します。
2回目のCtrl+Cは強制中断、SIGTERMは従来どおりプロセス終了です。

```text
pc-scanner progress: stage=scanning elapsed=12.0s finished=3 pending=7 reused=2 checkpoint=saved saved_parts=3
```

- `stage` は待機（`waiting` / `waiting_checkpoint`）、事前確認（`preflight`）、定義確認（`definitions`）、
  再開時の確認（`resuming`）、検査（`scanning`）、保存（`saving`）、任意の更新情報照会（`updates`）などを示します。
  最後は `completed`・`partial`・`cancelled`・`timed_out`・`error` です。MCPの取消処理中は `cancelling` になる場合があります。
- `elapsed` は呼び出し開始からの経過秒数。`finished` は今回結果を得た対象数（再利用・一部確認の結果も含む）、
  `pending` は現在把握できた未処理・再試行対象数、`reused` は今回再利用した対象数です。これらはファイル数ではありません。
  分割・失敗で残りは増える場合があり、確定前は `unknown`（JSONでは `null`）。合計や割合を推測しません。
- `checkpoint=saved` と `saved_parts` は、最後に成功したチェックポイントの置き換えと、そこに含まれる結果レコード数です。
  これは今回の終了数とは別で、未確認の過去レコードを含む場合があります。`write_failed` は最新の保存失敗を示し、
  `saved_parts` はその前の保存成功件数を保持します。`unavailable` は再開データを利用できない状態です。
  `not_started` は今回まだ再開データの確認・保存をしておらず過去の保存有無は不明、`not_applicable` は通常検査など保存対象外です。
- 結果の `data.progress` に同じ情報（経過時間は `elapsed_seconds`）を返します。通知にはファイル名・所見・生のエンジン出力を含めません。

MCPは進捗通知に対応したクライアントへ、状態変化を最大毎秒1回、変化がなくても既定10秒ごとに通知します。
検査前の定義確認結果は、フォルダー走査に入る前に別途通知します（送信待ちは最大1秒）。
通知値は経過秒数で、`total` は指定しません。Android・Wazuhなどは段階・経過時間を示し、取得していない対象数は不明のままです。
表示方法はクライアントによります。

クライアントがキャンセルした後は通知を送りません（MCPの進捗通知は、処理中の要求にしか使えないため）。
最後の保存状況は `get_scan_progress(scan_id="通知または結果のID")` で確認してください。IDを省くと直近の検査要求の状態を返します。
待機中・中止処理中なら、終了状態になるまで照会できます。この照会は保存済みの検査結果やファイル名を読みません。
保持するのはサーバーのメモリー内の直近32要求だけで、古いIDや再起動後のIDはエラーになります。
進捗の記憶が消えても、再開用チェックポイントは別に残ります。

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
  取得済みのファイルは検査します。除外指定の長さが上限を超えた場合は、上記の分割検査に切り替えます。
  その他の理由で安全に渡せない場合は、通常検査では検査を開始せず `partial` を返します。
  ClamAV は除外条件をパスの先頭512バイト（UTF-8）としか照合しないため、パスが512バイト以上の未取得ファイルがある場合も
  （ちょうど512バイトだと、それで始まるより長いパスまで除外してしまう）、
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
  （`data.freshness` は `unverified` のまま）、追加確認を無効にしていると接続状態も分かりません。
- `[wazuh.freshness]` の `enabled = true` と `manager_url`（末尾の `/` がない HTTPS origin）、必要なら絶対パスの
  `ca_file` を設定すると、最終通信日時とOSレコード日時を補足します。認証は別の環境変数
  `PC_SCANNER_WAZUH_MANAGER_USER` / `PC_SCANNER_WAZUH_MANAGER_PASSWORD` を使い、対象エージェントの必要な読取だけを許可してください。
  設定した `agent:id` だけに `agent:read`・`syscollector:read` を付与し、全端末向けのreadonlyロールは使いません。
  WazuhのRBACでは同じ端末の他のインベントリ・有効設定も読めるため、OSだけに制限したアカウントではありません。
  `max_keepalive_age_seconds` は既定300秒、`max_os_record_age_seconds` は7200秒（各1〜604800秒）。古い・欠落・取得失敗は
  所見を保持したまま `partial` とします。最近の情報でも脆弱性照合の完了は証明できず、`freshness` は `unverified` のままです。
  パッケージのレコード時刻の古さで収集停止を判定しません。追加通信は共通の全体期限内で合計最大5秒です。
  詳細保存が無効でも、固定の状態と正規化した時刻だけを要約履歴に保存し、ダッシュボードはページ群の最も古い観測と最悪の状態を表示します。
  [設計書](docs/wazuh-freshness-design.md)も参照してください。
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
  制御文字・書式文字・行区切りと、そのほかの見えない文字（双方向制御文字・ゼロ幅文字・タグ文字・異体字セレクター）は
  `\uXXXX`（U+FFFF を超えるものは `\UXXXXXXXX`）、UTF-8 でないバイトは `\xNN` で示し、名前は256文字
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
  検証に失敗したときは、理由（ホスト名の不一致や、発行元が分からないなど）を示します。
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

## 開発用ランタイム

開発基準は Python 3.15.2（`.python-version`）と Node.js 26.12.1（`.node-version`）です。
Node.js 26はCurrent版で、CIではNode.js 24 LTSと最低対応の22も確認します。
利用者向けの最低要件はPython 3.11以上・Node.js 22以上のままです。

Python本体を更新しても既存の仮想環境の処理系は変わらないため、3.15の開発環境を別に作ります。

```sh
python3.15 -m venv .venv-dev
.venv-dev/bin/python -m pip install --upgrade pip
.venv-dev/bin/python -m pip install '.[agent]'
.venv-dev/bin/python -m unittest discover -s tests -v
PC_SCANNER_NPM_E2E=1 PC_SCANNER_PYTHON="$PWD/.venv-dev/bin/python" npm test
```

Windowsでは `py -3.15 -m venv .venv-dev` と `.venv-dev\Scripts\python.exe` を使います。
同梱の適合性スナップショットは引き続きCPython 3.14用です。npm起動時はハッシュで検証できる処理系を優先し、
3.15では同じ固定バージョンをwheelハッシュなしで導入してstderrに通知します。
3.15用スナップショットはCompliance profilesワークフローの処理系選択から各OSで新規生成できます。
既存プロファイルを維持するため、選択の既定値は3.14です。

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
- MCP のテストには `agent` extra が必要です。システムの `python3` など、未導入の Python で実行するとスキップされます。
  実際にサーバーを起動して接続・ツール一覧・呼び出しを確認し、長時間の検査中の応答・順番待ち・進捗通知はメモリ内の接続で確認します。
- GitHub Actionsは、`main`へのpushとプルリクエストのたびに、Windows / macOS / Linux × Python 3.11 / 3.14 / 3.15でテストを実行する設定です。
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
  （macOS / Linux）起動用スクリプトへのSIGTERMでサーバーも止まることを確認します。
  CIでは各OSでPython/Node.jsを3.11/22・3.14/22・3.14/24・3.15/26の組合せで確認します。
  公開前の試験は3.14/24と3.15/26の両方で行い、公開処理自体はNode.js 24 LTSで実行します。
  3.14のジョブは`PC_SCANNER_NPM_EXPECT_HASHED=1`を設定し、ハッシュなし導入に落ちたら改ざん試験を省略せず失敗させます。
  あわせて`PC_SCANNER_NPM_AUTO_DISCOVER=1`で`PC_SCANNER_PYTHON`の指定を外し、実際の配布物の自動探索を通します。
  他のジョブは指定した処理系を試すため、明示指定を維持します。
- Linux arm64コンテナの受入試験（2026-10-19）：Ubuntu 24.04上で実osquery 5.23.1・ClamAV 1.5.4を一般ユーザーで実行。
  ホストのマウント・実行時ネットワークなしで、インベントリ、EICAR、日本語名、リンク、深度・サイズ・権限制限、定義の鮮度、
  実CLIとMCP stdioの進捗・キャンセルを確認しました（[記録](docs/acceptance/linux-arm64-container-2026-10-19.json)）。
  確認範囲はコンテナ内であり、物理Linuxホストや他ディストリビューション、Linux側freshclam更新は未確認です。
- 実際のエンジンでの検出精度や、各 OS での動作は保証していません。配布前に、各 OS の実機での受入試験が必要です。

## 関連ドキュメント・ライセンス

脆弱性の報告は [SECURITY.md](SECURITY.md)（英語・日本語）を参照してください。公開の Issue には書かないでください。

- [docs/backlog.md](docs/backlog.md)：未対応の課題と、実機で確認すべき項目
- [docs/licensing.md](docs/licensing.md)：ライセンス方針と配布前チェック
- [docs/compliance.md](docs/compliance.md)：SBOM・第三者表示の対象範囲と再生成手順
- [docs/releasing.md](docs/releasing.md)：npm パッケージのリリース手順（GitHub Actions からのステージド公開）
- [profiles/](profiles/)：Windows・Linux・Intel Mac 向けのロック・SBOM・第三者表示（直下は macOS arm64 の参照版）
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)・[CycloneDX SBOM](sbom/python-agent.cdx.json)：MCP 用 Python 依存パッケージの表示

独自コードのライセンスは [MIT License](LICENSE)（Copyright (c) 2026 tedorigawa001）です。
選んだ理由は [docs/license-recommendation.md](docs/license-recommendation.md) にあります。第三者のコンポーネントはそれぞれのライセンスのままです。
このリポジトリは Wazuh・osquery・ClamAV のコード、バイナリ、ルール、定義ファイルを含みません。
