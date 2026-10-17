# 家庭用ルーター対応（第1段階）の設計

所有者自身の家庭用 Wi-Fi ルーターを、**ルーターに一切アクセスせずに**点検する。所有者が書いたメーカー・機種・ファームウェアの
バージョンを公開の脆弱性情報と照合し、管理画面で所有者が確かめた設定を、公的な推奨と照らし合わせる。
既存の方針（固定の操作だけ・読み取り専用・外から来る文字列は信用しない・「安全」とは判定しない）をそのまま当てはめる。

状態：第1段階を実装済み（2026-10-17、`pc_scanner/router.py`）。下の「要判断」は所有者が推奨どおりに決めた。
調査結果は 2026-10-17 時点のもので、出典の URL を併記した。実際の MyJVN API で、例の機種（WSR-300HP、ファームウェア 2.40）を
照会し、2件の脆弱性情報のうち1件が `affected`、もう1件が「該当しない」になることを確かめた。
受入試験の記録：[MyJVN](acceptance/router-myjvn-2026-10-17.json)（実際の API で製品の候補の取得と、「Ver.2.55より前」の境界
＝ 2.54 は `affected`、2.55・2.56 は「該当しない」）、[CISA KEV](acceptance/router-cisa-kev-2026-10-17.json)（実際のカタログ 1,748 件で、
NAS の項目が混じらないこと、「DIR-85」が「DIR-859」に一致しないことなど）。どちらも公開の機種名と試験用の値だけを使い、
ルーターにはアクセスしていない。

## 目的と範囲

**第1段階で確かめること**

| 項目 | 方法 |
|---|---|
| 既知の脆弱性 | 機種を JVN iPedia（MyJVN API）で照会し、公表済みの脆弱性と、それぞれの影響を受けるバージョンを返す。所有者が書いたファームウェアのバージョンと比べられる場合は比べる |
| 悪用が確認された脆弱性 | 所有者が取得した CISA KEV（Known Exploited Vulnerabilities）と、メーカー名・機種名で照合する |
| サポート終了 | 所有者が、メーカーのサポート終了一覧で確かめた結果を設定に書く（機械で読める一覧がないため） |
| 設定 | 所有者が管理画面で確かめた設定（自動更新・初期パスワードの変更・遠隔管理など）を、公的な推奨と照らし合わせる |

**第1段階で扱わないこと**

- **ルーターへのアクセス全般**。ネットワーク越しの調査（ポート調査・脆弱性スキャン）、管理画面へのログイン、UPnP などでの問い合わせも
  行わない。ルーターに想定外の影響を与えうるうえ、調査と攻撃の境目があいまいになるため
- パスワードの試行、既定のパスワードでのログインの確認
- 攻撃用のツール（RouterSploit、Metasploit、THC-Hydra など）の利用や同梱
- ファームウェアのイメージの解析（EMBA、FACT など）と、通信の傍受（IoT Inspector など）
- ルーターの設定の変更・ファームウェアの更新。所有者がメーカーの手順で行う

## 前提と安全上の注意

- **本人のルーターだけ**を対象にする。点検できるのは、所有者が設定ファイルに書いたルーターだけ（下の「設定」）。AI はエイリアスでしか指定できない。
- **ルーターの管理者パスワードは扱わない**。設定ファイルに `password` などのキーがあれば、Wazuh の認証情報と同じく、削除を促す警告を出す。
- **バージョンは所有者が書いた値**で、実機と違うかもしれない。結果に「所有者が書いた値に基づく」と明記する。
- **設定の回答は所有者の申告**。このツールは確かめられない。回答がない項目は「未確認」とし、「問題なし」とはしない。
- JVN と KEV に載るのは**公表された脆弱性だけ**。該当なしは安全の証明にならない。結果の警告と README に明記する。
- **機種名が外部に送られる**（下の「照合データ」の MyJVN API を使う場合）。README に明記し、所有者が有効にしたときだけ問い合わせる。

## 設定

```toml
[router]
# MyJVN API に機種を問い合わせる（既定は false）。下の「要判断」1
jvn_lookup = false
# 所有者が取得した CISA KEV の JSON の絶対パス（空欄なら照合しない）
kev_file = ""
# KEV のカタログがこれより古いと partial（既定 30 日）
max_kev_age_days = 30
# 設定の確認がこれより古いと partial（既定 180 日）
max_check_age_days = 180

# 「エイリアス = 機種の情報」。AI はエイリアスでしか指定できない
[routers.home]
maker = "buffalo"               # 下の「メーカー」の表のいずれか、または "other"
model = "WSR-0000AX"            # 管理画面や本体のラベルの表記のまま
firmware = "1.00"               # 管理画面に表示されるバージョン
jvn_cpes = []                   # JVN の CPE（下の「機種の特定」）。例：["cpe:/h:buffalo_inc:wsr-0000ax"]。空なら JVN の照会をしない
support = "supported"           # supported | ended | unknown（メーカーのサポート終了一覧で確認）
checked_on = 2026-10-17         # 管理画面で下の設定を確かめた日

[routers.home.settings]
auto_update = true              # ファームウェアの自動更新
admin_password_changed = true   # 管理画面のパスワードを初期値から変えた
remote_admin = false            # インターネット側からの管理（遠隔管理）
vpn_server = false              # 使っていない VPN サーバー機能
ddns = false                    # 使っていない DDNS
upnp = false                    # UPnP
wps = false                     # ボタン一つでの接続設定（WPS）
wifi_security = "wpa3"          # wpa3 | wpa2-aes | wpa2-tkip | wep | open
unknown_vpn_accounts = false    # 覚えのない VPN アカウントがある
```

- 値はすべて所有者が書く。AI に書かせない（既存の設定ファイルと同じ）。
- 知らないキーは既存の仕組みで候補つきの警告にする。`settings` の未記入は「未確認」として扱う。

## MCP ツールと CLI

| MCP ツール | CLI | 内容 |
|---|---|---|
| `check_router(router_alias)` | `router-check <router_alias>` | 登録したルーターを点検する |
| —（所有者だけが使う） | `router-products <maker> <keyword>` | MyJVN の製品の候補（CPE）を一覧にし、所有者が `jvn_cpes` に書くものを選ぶ |

- `check_router` は読み取り専用の注釈を付ける。MyJVN を使う設定のときは、外部と通信するため `openWorldHint` を true にする。
- 結果は既存の形（`schema_version`・`status`・`findings`・`warnings`・`data`）で返し、スキャン履歴とダッシュボードにも載る。

## 照合データ

### JVN iPedia（MyJVN API）— 第1段階の主な照合先

- 国内の主要メーカーが登録されている（2026-10-17 に API で確認）。

  | メーカー | vendorId | ベンダーの CPE | 製品数 |
  |---|---|---|---|
  | バッファロー | 86 | `cpe:/:buffalo_inc` | 243 |
  | NEC（Aterm） | 89 | `cpe:/:nec` | 323（Aterm は約107） |
  | アイ・オー・データ | 385 | `cpe:/:i-o_data_device` | 111 |
  | エレコム | 18753 | `cpe:/:elecom` | 163 |

- API：`https://jvndb.jvn.jp/myjvn?method=…&feed=hnd`（[説明](https://jvndb.jvn.jp/apis/index.html)）。使うのは
  `getProductList`（機種の候補）と `getVulnOverviewList`（機種の脆弱性の一覧）、`getVulnDetailInfo`（影響を受けるバージョン）だけ。
  照会には CPE 2.2 の `cpeName` を使う（下の「機種の特定」）。出力は XML。
- 利用条件：[利用規約](https://jvndb.jvn.jp/apis/termsofuse.html)では無償・無保証。[API の説明](https://jvndb.jvn.jp/apis/index.html)では、
  アプリが表示する情報に MyJVN API から提供されたものである旨を表示するよう協力を求めている。
  [FAQ](https://jvndb.jvn.jp/apis/myjvnapi_faq.html)では商用利用に特に制限を設けず、短時間の収集なら毎秒2〜3件程度に抑え、
  差分の取得を検討するよう求めている。結果の `data` と README に「出典：MyJVN API（IPA）」を表示する。
- 影響を受けるバージョンは自由記述（VULDEF の `AffectedItem/VersionNumber`）で、機械的に比べられないことがある（下の「バージョンの比較」）。

#### 検索期間（常に全期間）

MyJVN API は、発見日・更新日・発行日のパラメーターを省くと、それぞれ既定の「過去1週間」で絞る
（[FAQ Q2-6](https://jvndb.jvn.jp/apis/myjvnapi_faq.html)）。省くと、古いまま修正されていない脆弱性が照合から漏れる。
実際に 2026-10-17 に `cpeName=cpe:/*:buffalo_inc:wsr-300hp` で照会すると、範囲指定なしでは2件（2026 年と 2017 年の公表）、
日付のパラメーターを省くと0件だった。
そのため `getVulnOverviewList` には毎回 `rangeDatePublic=n&rangeDatePublished=n&rangeDateFirstPublished=n`（範囲指定なし）を付ける。
第1段階はキャッシュも差分の取得もせず、点検のたびに全期間を照会する（機種ごとの件数は少なく、古い情報を使うおそれもない）。
差分の取得は第2段階で検討する。

#### 取得の範囲と打ち切り

- 1回の応答の上限は、概要の一覧（`getVulnOverviewList`）が50件、詳細（`getVulnDetailInfo`）が10件
  （[概要の API](https://jvndb.jvn.jp/apis/getVulnOverviewList_api_hnd.html)、[詳細の API](https://jvndb.jvn.jp/apis/getVulnDetailInfo_api_hnd.html)）。
  51件目以降は `startItem` で続きを取り、総数は応答の `totalRes` で分かる（[FAQ Q5-1](https://jvndb.jvn.jp/apis/myjvnapi_faq.html)）。
- 概要は `totalRes` に達するまでページを進める。各ページの `firstRes` と `totalResRet` が続いているか、エラーコード（`retCd`・`errCd`）が
  ないかを確かめる。詳細は、得られた ID を10件ずつまとめて取得する。
- 1回の点検で扱う脆弱性情報は200件まで（概要4ページ・詳細20回、要求は1秒に1回まで）。全体の期限（`local.timeout_seconds`）とキャンセルにも従う。
- **全件を取得できなかったら `partial`** にし、`data.sources.jvn` に総数・取得できた件数・取得できなかった件数と理由
  （`limit`：上限に達した、`deadline`：期限切れ、`error`：応答の異常や通信の失敗、`inconsistent`：ページの位置や件数が合わない）を返す。
  AI クライアントがキャンセルしたときは、ほかの操作と同じく点検全体を `error`（キャンセル）で終える。
  取得できなかった分は「該当なし」として扱わない。警告にも件数と理由を書く。
- 概要は取れたが詳細を取れなかった脆弱性は、所見に `comparison: "unknown"`（理由 `detail_missing`）として残す。
- **2027 年からの変更**：[告知](https://jvndb.jvn.jp/nav/sys_announce.html)では、JSON 出力・CPE 2.3・新しい製品 ID（JVNPID）・
  2026 年以降の登録分のバージョンでの絞り込みを備えた新しい API に移る。フィードの URL が変わり、移行中は最大 7 日ほど止まる。
  照会部分は差し替えやすいよう分け、新しい API が使えるようになったら移る。

### CISA KEV — 悪用が確認された脆弱性

- 所有者が取得する（このツールはダウンロードしない。Android の指標と同じ扱い）。
  JSON：`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`（約 1.8 MB、1,748 件）。
- ライセンス：[CC0 1.0](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)。CISA のロゴを使ったり、推奨を受けたように見せたりしない。
- 各項目にバージョンの範囲も CPE もなく、`vendorProject`・`product` は自由記述（例："DIR-859 Router"、"Multiple Routers"）。
  そのためメーカー名と機種名の照合は**確認を勧める所見**（`review`）にとどめ、「該当する」とは断定しない。
  - 機種名は、製品名を空白・カンマ・スラッシュなどで区切った語の、連続する1〜4語と一致したときだけ一致とする（大文字小文字と
    ハイフンは区別しない）。部分文字列では比べない（「DIR-85」を「DIR-859」と取り違えない）。
  - 機種名が一致しない場合、同じメーカーのルーター全般の項目（製品名に「multiple」と「router」を含むもの）だけを `maker_only` とする。
    NAS・カメラなどの「Multiple ... Devices」は含めない。
- ルーターのメーカーは D-Link・Zyxel・NETGEAR・TP-Link・DrayTek・ASUS などが中心で、国内メーカーはほとんど載っていない（バッファローは0件）。
  サポート終了の製品に「切り離すべき」と書いた項目もあり、それも所見に含める。
- カタログの `dateReleased` が `max_kev_age_days` より古いと `partial` にする。経過時間は日数に切り捨てずに厳密に比べる
  （ClamAV の定義や Android の指標と同じ）。

### 使わないもの（理由）

- **NVD**：2026-04-15 から、製品の情報（CPE）を付けるのは KEV に載るものなどに限られ、それ以外は後回しとされた
  （[告知](https://www.nist.gov/itl/nvd)）。国内メーカーの家庭用ルーターは付かないことが多い。無認証の上限も 30 秒に5件と少ない。
- **CVE List（cvelistV5）**：数 GB と大きく、再配布には MITRE の著作権表示を伴う必要がある（[利用規約](https://www.cve.org/Legal/TermsOfUse)）。
- **endoflife.date**：家庭用ルーターのメーカーを扱っていない（OpenWrt や RouterOS などの OS だけ）。
- **メーカーのサポート終了一覧**：どのメーカーも HTML か PDF だけで、機械で読める形がない。所有者が確かめて `support` に書く。
  README には各メーカーの一覧と、それをまとめた [NOTICE のページ](https://notice.go.jp/end_of_support) へのリンクを載せる。

## 機種の特定

機種名の表記ゆれ（`h:` と `o:`、`_firmware` の有無、重複した登録）があるため、自動では決めない。

1. 所有者が `router-products buffalo WSR-0000` を実行すると、MyJVN の `getProductList`（vendorId で絞る）から候補の製品名と CPE を一覧にする。
2. 所有者が候補から選び、CPE を `jvn_cpes` に書く。同じ機種が別の名前で登録されていれば、それも書く。
3. 詳細の `AffectedItem` には製品 ID がなく CPE だけがあるため、製品は CPE で扱う。同じ機種でも `h:` と `o:` が混在する
   （例：2026-10-17 に確認した JVNDB-2026-035794 では、同じ情報の中で `cpe:/o:buffalo_inc:wex-g300` と `cpe:/h:buffalo_inc:wsr-300hp`）。
   そのため照会と照合では、CPE の `{part}` を区別せず、`{vendor}:{product}` の完全一致（大文字小文字を区別しない）で扱う。
   照会は `cpeName=cpe:/*:{vendor}:{product}` で行う（`{part}` に `*` を指定できる）。`_firmware` を付け外しするなどの推測はしない。
4. `jvn_cpes` が空なら JVN の照会はせず、点検は `partial` にする。

## バージョンの比較

1つの脆弱性情報に複数の製品が載り、製品ごとに影響を受けるバージョンが違うことがある（上の JVNDB-2026-035794 では、
WEX-G300 が「Ver.1.71より前」、WSR-300HP が「Ver.2.55より前」）。別の機種の範囲で比べると、誤って「該当しない」になる。

- 比べるのは、**`jvn_cpes` のいずれかと `{vendor}:{product}` が一致する `AffectedItem`** の `VersionNumber` だけ。製品名
  （`ProductName`）の文字列では結び付けない。
- 一致する `AffectedItem` がない、または CPE がない `AffectedItem` しかないときは、対応が分からないので `comparison: "unknown"`
  （理由 `product_not_matched`）とし、所見に残す。ほかの製品の範囲は使わない。
- 一致する `AffectedItem` が複数ある、または `VersionNumber` が複数あるときは、すべてと比べる。どれか1つでも影響を受ければ `affected`。
  すべてを比べられ、どれにも当たらないときだけ `not_affected`。比べられないものが1つでもあれば `unknown`（理由 `version_not_parsed`）。
  `VersionNumber` のない `AffectedItem` も「比べられないもの」として数える（どのバージョンにも当てはまりうるため、無視しない）。
- 記述が決まった形（例：「Ver.2.55より前のバージョン」「Ver.2.55 およびそれ以前」）で、所有者のバージョンも数字の並びとして読めるときだけ
  比べる。バージョン番号として比べた結果と小数として比べた結果が食い違うとき（「2.6」と「2.55」、「1.07」と「1.7」）は、メーカーの番号の
  付け方次第で答えが変わるため、比べられないものとして扱う。比べられない記述は、所見に記述をそのまま添えて「要確認」とし、所有者がメーカーの告知で確かめるよう促す。断定はしない。
- `affected` と `unknown` は所見にし、`not_affected` は所見にせず `data` に件数と ID を残す。
- 新しい JVN の API でバージョンでの絞り込みが使えるようになったら、それを優先する。

## 設定の照らし合わせ

公的な推奨（下の「出典」）にある項目だけを扱う。

| 項目 | 推奨 | 推奨に反する場合 |
|---|---|---|
| `admin_password_changed` | 初期値・簡単なものから変える | `high` |
| `auto_update` | 自動更新を有効にする | `medium` |
| `support` | サポート終了の機種は買い替える | `ended` なら `high`、`unknown` なら未確認 |
| `remote_admin`・`vpn_server`・`ddns` | 使っていなければ無効にする | `medium`（使っている場合は所有者が判断できるよう、理由とともに確認を促す） |
| `unknown_vpn_accounts` | 覚えのない VPN アカウントがないか確かめる | `high`（初期化とファームウェアの更新を促す） |
| `upnp`・`wps` | 使っていなければ無効にする | `low` |
| `wifi_security` | WPA3 か WPA2（AES） | `wpa2-tkip` は `medium`、`wep`・`open` は `high` |

- 回答のない項目は所見にせず、警告に「未確認」と並べて `partial` にする。
- `checked_on` が `max_check_age_days` より古いと、確認し直すよう促して `partial` にする。

## 結果の形

```json
{
  "schema_version": 1, "source": "router", "status": "partial",
  "findings": [
    {"kind": "known_vulnerability", "severity": "high", "id": "JVNDB-2026-000000", "title": "...",
     "matched_cpe": "cpe:/h:buffalo_inc:wsr-0000ax", "affected_versions": ["ファームウェア Ver.1.10 およびそれ以前"],
     "comparison": "affected"},
    {"kind": "known_vulnerability", "severity": "medium", "id": "JVNDB-2025-000000", "title": "...",
     "matched_cpe": null, "affected_versions": [], "comparison": "unknown", "reason": "product_not_matched"},
    {"kind": "setting", "severity": "medium", "item": "auto_update", "value": false}
  ],
  "warnings": ["Based on the maker, model and firmware version the owner entered; the router itself was not contacted",
               "Settings not confirmed: wps, upnp"],
  "data": {"router_alias": "home", "maker": "buffalo", "model": "WSR-0000AX", "firmware": "1.00",
           "support": "supported", "checked_on": "2026-10-17",
           "sources": {"jvn": {"queried": true, "attribution": "MyJVN API (IPA)", "date_range": "all",
                               "total": 4, "fetched": 4, "not_fetched": 0, "not_fetched_reason": null,
                               "not_affected": ["JVNDB-2024-000000", "JVNDB-2023-000000"]},
                       "kev": {"catalog_version": "2026.10.16", "matches": 0}}}
}
```

- `status` は、JVN の照会が成功し、KEV が新しく、設定がすべて回答済みで新しいときだけ `completed`。それでも「安全」とは言わない。
- JVN や KEV から来た文字列（題名・記述）は、既存の `clean_text` で制御文字をエスケープし、長さを制限する。

## 実装上の注意

- MyJVN への通信は Wazuh と同じ方針にする：HTTPS のみ・証明書を検証・プロキシとリダイレクトを使わない・全体の期限とキャンセル・
  出力の上限。送るのは固定のパラメーターと所有者が書いた CPE だけ。件数と間隔の上限は上の「取得の範囲と打ち切り」のとおり。
- XML は大きさを制限し、文書型宣言（DTD）を含むものを解析する前に拒否する（実体の宣言は DTD の中にしか書けず、展開による攻撃を
  避けるため）。判定はバイト列の検索ではなく expat の文書型宣言のハンドラーで行い、UTF-16 などの文字コードでも見逃さない。
- KEV の JSON は、Android の指標と同じく、型を確かめ、壊れた項目は数えて飛ばし、大きさを制限する。
- ルーターの照合は PC のエンジンと独立させ、`pc_scanner/router.py` に分ける。

## テスト

- MyJVN の XML（実際の応答の形に沿った架空の内容）と KEV の JSON の見本で、照合・バージョンの比較・未確認の扱いを確かめる。
- バージョンの比較は、比べられる形・比べられない形・境界の値を表で網羅する。
- **検索期間**：日付のパラメーターを省くと過去1週間に絞る代役のサーバーで、何年も前に公表され修正されていない脆弱性が
  見つかること（省くと0件になる回帰を検出すること）と、要求に3つの `=n` が必ず付くことを確かめる。
- **取得の範囲**：総数が50件を超えるとページを進めること、上限・期限・キャンセル・途中のエラー・`firstRes` や件数の食い違いで
  打ち切ったときに `partial` になり、取得できなかった件数と理由が返ること、取得できなかった分を「該当なし」にしないことを確かめる。
  詳細が取れなかった脆弱性が `unknown` で残ることも確かめる。
- **製品への結び付け**：複数の製品が載る脆弱性情報で、別の機種の範囲では「該当しない」になる組み合わせでも、設定した CPE の範囲で
  `affected` になること。一致する `AffectedItem` がなければ `unknown`（`product_not_matched`）になること。`h:` と `o:` の違いでは
  一致し、製品名が似ているだけでは一致しないことを確かめる。
- 通信の失敗・期限切れ・キャンセル・リダイレクト・大きすぎる応答・DTD を含む XML・壊れた JSON を、それぞれ `error` か `partial` にする。
- 設定に `password` があると警告が出ること、AI がエイリアス以外を指定できないことを確かめる。
- 規則をわざと壊した変更（照合を外す、未確認を「問題なし」にする、DTD を通す、など）をテストが検出することを確かめる。

## 要判断（所有者が決める）

2026-10-17、所有者が3点とも推奨どおりに決めた（MyJVN は既定で無効・所有者が有効にしたときだけ問い合わせる、KEV を加える、
設定の回答は設定ファイルに書く）。

1. **MyJVN API に問い合わせるか**：問い合わせると国内メーカーの脆弱性が分かるが、機種名が IPA に送られ、外部との通信が増える。
   推奨は「所有者が有効にしたときだけ問い合わせる（既定は無効）」。もう一つの案は、所有者が JVN のフィードを取得して渡す方式
   （通信はないが、フィードが大きく、2027 年に URL と形式が変わる）。
2. **KEV を照合に加えるか**：海外メーカーのルーターには有効だが、国内メーカーはほとんど載っていない。推奨は「加える（所有者が取得）」。
3. **設定の回答を設定ファイルに書く形でよいか**：推奨は「設定ファイル（所有者だけが編集）」。AI との会話で回答を集めて書かせることはしない。

## 第2段階の候補（今回は設計しない）

- **新しい JVN の API（2027 年〜）への移行**：JSON・CPE 2.3・バージョンでの絞り込みにより、比べられる範囲が広がる。
- **LAN 内での機種の確認（所有者が選んだ場合だけ）**：UPnP の機器情報ではメーカー名と機種名は必須だが、ファームウェアのバージョンはない
  （[UPnP Device Architecture 2.0](https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf)）。
  ルーターへの問い合わせになるうえ、UPnP は無効にするよう推奨されているため、第1段階の方針（ルーターにアクセスしない）とは別に検討する。
- **JC-STAR のラベルの表示**：IPA の制度（[JC-STAR](https://www.ipa.go.jp/security/jc-star/)）に対応した機種かどうか。
- **機械で読めるサポート終了の情報**が公開された場合の照合。

## 出典（設定の推奨）

- 警察庁（ルーターのメーカーと共同、2023-03-28）：[注意喚起](https://www.npa.go.jp/bureau/cyber/pdf/20230328_press.pdf)
  — 初期パスワードの変更、ファームウェアの更新、サポート終了の機種の買い替え、覚えのない VPN・DDNS・遠隔管理の確認
- 総務省「自宅 Wi-Fi 利用者向け簡易マニュアル」（2025 年2月版）：[PDF](https://www.soumu.go.jp/main_content/000989912.pdf)
  — 暗号化方式（WPA3・WPA2 の AES）、使わない機能（VPN・DDNS・遠隔管理・WPS・UPnP・DMZ）を無効に
- NOTICE（総務省・NICT・ICT-ISAC）：[安全な使い方](https://notice.go.jp/safety)、[サポート期間の一覧](https://notice.go.jp/end_of_support)
- 警察庁・総務省・NICT（2026-07-21）：家庭の IoT 機器が「レジデンシャルプロキシ」に悪用される事例の報告
  （[PDF](https://www.npa.go.jp/bureau/cyber/pdf/20260721-1_residentialproxy.pdf)）。ルーターも対象に挙げている
- FBI（2025-05-07）：サポート終了のルーターの買い替え、遠隔管理の無効化（[PSA](https://www.ic3.gov/PSA/2025/PSA250507)）
- routersecurity.org のチェックリスト（[checklist](https://routersecurity.org/checklist.php)）
