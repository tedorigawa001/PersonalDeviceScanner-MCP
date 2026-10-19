# Wazuh の鮮度確認の設計

状態：第1段階を実装（2026-10-19、`pc_scanner/freshness.py`）。Manager API を任意で併用し、エージェントの接続状態と収集レコードの時刻を追加する。
脆弱性インデックスの全件が最新のインベントリ・定義で照合済みかは、これらの情報だけでは証明できないため、
既存の `data.freshness = "unverified"` を維持する。既存環境の設定変更・アカウント作成は行わない。

## 実環境で確認したこと

対象は既存の Wazuh 4.14.9 とコンテナのエージェント001。Mac本体のインベントリではない。
既存の Manager API アカウントを使用し、コンテナ内の `https://localhost:55000` に問い合わせた。
既存の API 証明書を明示的に信頼し、SAN の `localhost` を検証した。証明書検証を無効にはしていない。
認証用 POST と読取用 GET のみを使い、設定変更・再起動・収集の強制開始・パッケージ変更は行っていない。

| 問い合わせ | 確認結果 |
|---|---|
| `GET /agents?agents_list=001&select=id,name,status,lastKeepAlive&limit=1` | 対象001の接続状態と最終通信時刻を取得できる |
| `GET /syscollector/001/os?select=scan.id,scan.time` | OSレコードの時刻を取得できる。完了時刻という保証はない |
| `GET /syscollector/001/packages?select=scan.id,scan.time&limit=5&sort=-scan.time` | パッケージごとのレコード時刻を取得できる |
| 上記 packages の `distinct=true&limit=100` | 異なる時刻が14種類あり、全パッケージ共通の最新収集時刻ではない |
| `GET /agents/001/config/wmodules/wmodules` | 有効な設定は interval=3600秒、scan-on-start=yes、packages/os有効 |

`select=scan` は400・エラー1724だった。`select=scan.id,scan.time` は成功したため、親オブジェクト名での選択を実装に使わない。
`scan.id` は今回の応答では0であり、単調増加する収集世代IDとして使用しない。
APIの `error`、`total_failed_items`、`failed_items` も検査し、HTTP 200だけで成功としない。

12:40 UTC時点で、エージェントのログには11:43:20〜11:43:21 UTCの収集がある一方、
OSの `scan.time` は11:43:20 UTC、パッケージの時刻は前日の22:42:39〜22:42:54 UTCだった。
したがって、パッケージの時刻の最大値が古くても「定期収集が止まっている」とは判定しない。
自然な定期収集（12:43:23開始、12:43:24終了）の前後でも比較した。OS時刻は11:43:20から12:43:23へ進み、
収集終了ではなく開始に一致した。パッケージ115件の選択した内容のSHA256と14種類のレコード時刻は変化しなかった。
日時はすべて2026-10-19 UTC（パッケージのレコード時刻は前日）。
観測値は[調査記録](acceptance/wazuh-manager-freshness-2026-10-19.json)を参照。

## 時刻の意味と更新条件

4.14.9の[Syscollector実装](https://github.com/wazuh/wazuh/blob/v4.14.9/src/wazuh_modules/syscollector/src/syscollectorImp.cpp)では、
`scan()` 開始時に内部の `m_scanTime` を設定し、`notifyChange()` の差分通知にその値を付ける。
同期処理では送信時刻を付ける経路もある。Manager APIのレコード時刻は、全収集の完了を表す共通の時計として扱えない。
初期同期・差分更新・再同期で変わる可能性があり、古いレコード時刻だけで未収集・停止を断定しない。
パッケージ追加・削除・更新を起こす介入試験はしていないため、その全経路での時刻更新は実機検証済みとはしない。

[公式の収集データ例](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/viewing-system-inventory-data.html)にも
レコードの `scan.time` があるが、脆弱性照合の完了時刻とは説明されていない。
[脆弱性検出の説明](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)では、
収集インベントリと脆弱性情報を照合する。接続、収集、差分同期、照合、インデックス反映を別の段階として扱う。

| 情報 | 表示してよい意味 | そこから判断しないこと |
|---|---|---|
| ローカルの取得日時 | MCPがその情報を取得した日時 | その時刻に検査された |
| `lastKeepAlive` と `status` | Managerが記録した接続状態 | 全インベントリを収集・照合済み |
| OSの `scan.time` | OSレコードに付いた時刻 | packages/hotfixesも収集・同期済み |
| packagesの `scan.time` | パッケージレコードに付いた時刻 | 値が古ければ定期収集が停止中 |
| `vulnerability.detected_at` | その脆弱性を検出した時刻 | 最終照合日時や結果全体の鮮度 |
| 収集間隔の設定 | 設定上の予定 | 直近の収集が正常完了した |

## 第1段階の機能

`get_vulnerabilities` に任意の補足情報を追加する。MCPクライアントはURL・agent_id・閾値を指定できず、
所有者の設定だけを使う。既定では追加通信しない。`wazuh-monitoring-*` の15分単位の記録は収集完了の証拠にならず、
Indexer権限の拡張も必要になるため、第1段階では採用しない。

Manager APIでの取得は、認証、設定済み001だけのエージェント情報、001だけのOSレコードに限定する。
パッケージ一覧・設定取得・ログ取得は今回の意味検証用であり、通常のMCP呼び出しには追加しない。
完全なスキャン完了時刻を得るAPIがあるとは仮定しない。

### 設定

```toml
[wazuh.freshness]
enabled = false
manager_url = "https://manager.example:55000"
ca_file = "/absolute/path/to/manager-api-ca.pem"
max_keepalive_age_seconds = 300
max_os_record_age_seconds = 7200
```

- 2つの閾値はWazuhの既定値ではなく、本ツールの設計上の初期値。設定可能範囲は1〜604800秒、bool不可。
- `max_os_record_age_seconds` はOSレコードの古さを表示する目安であり、収集停止や脆弱性の古さを判定する閾値ではない。
- `manager_url` はHTTPSのoriginだけを許可。userinfo・クエリ・フラグメント・パスは拒否し、`ca_file` は絶対パスで検証する。
- 既存の設定検証にネストした節の許可キーを追加し、未知キーや設定内の秘密値も警告する。
- 認証情報は `PC_SCANNER_WAZUH_MANAGER_USER` / `PC_SCANNER_WAZUH_MANAGER_PASSWORD`。
  Indexerの認証情報を流用・自動フォールバックしない。追加機能が無効なら読み取る必要もない。
- 専用アカウントには `allow_run_as=false` とし、white modeで `agent:id:001` の `agent:read`・`syscollector:read` だけを許可する。
  4.14.9の実効ポリシーと対象002への403を確認済み。標準の管理者・全端末readonlyロールは付けない。
- このRBACはアクション単位のため、対象001のパッケージ一覧と有効設定も読める。OS・接続情報のエンドポイントだけに
  制限できたとはしない。本ツールの呼出先の制限と、アカウントの権限範囲を区別する。
  エンドポイント単位の分離が必要なら、許可リスト中継などを別途設計する。
  根拠：[公式RBACリファレンス](https://documentation.wazuh.com/current/user-manual/api/rbac/reference.html)。

### 通信と認証

1. 既存のIndexer検索を行い、所見を確保する。
2. 有効かつ残り時間がある場合だけManager APIへ認証し、JWTをメモリー内で使用する。
3. 固定のエージェント情報・OS情報エンドポイントをGETする。応答のIDが設定値と一致することを検証する。
4. 接続状態とOSレコードの観測値を追加し、JWTを履歴・結果・エラーに含めない。

初期実装は呼び出しごとに1回認証し、永続的なトークン保存・認証再試行はしない。
既存の最大30秒（またはlocal.timeout_secondsの短い方）を呼び出し全体の共通期限とし、Managerへの追加分は最大5秒か残り時間の短い方。
認証・各GETに別々の30秒を与えない。プロキシ・リダイレクトは使わず、TLSとホスト名を検証する。
Indexer用CAの互換処理をAPIへ無条件に広げない。既存API証明書は通常の検証で成功している。
認証応答は最大16 KiB、メタデータ応答は各256 KiBと既存max_output_bytesの短い方に制限し、
既存の通信中キャンセル・ソケット切断・補助スレッド終了処理を使う。
エラーは固定の分類で返し、URL、認証ヘッダー、JWT、API生応答を表示しない。

## 出力と状態

互換性のため `data.freshness` は文字列の `unverified` のまま、`data.freshness_evidence` を追加する。

```json
{
  "freshness": "unverified",
  "live_scan_triggered": false,
  "freshness_evidence": {
    "source": "wazuh_manager_api",
    "checked_at": "2026-10-19T12:40:44+00:00",
    "agent_connection": {
      "state": "recent",
      "last_keepalive_at": "2026-10-19T12:40:38+00:00"
    },
    "os_record": {
      "state": "recent",
      "recorded_at": "2026-10-19T11:43:20+00:00"
    },
    "assessment": "vulnerability_freshness_unverified"
  }
}
```

このJSONの通信時刻は形式例。実測値は受入記録を参照する。
各時刻はタイムゾーン必須でUTCへ正規化して再出力する。日時として解析できる文字列をそのまま返さない。
判定は丸める前のtimedeltaで行い、閾値ちょうどは `recent`、1マイクロ秒超過で `aged`。
未来時刻は60秒までは時刻ずれとして警告して経過0秒、60秒超は `unknown`。無効日時・欠落も `unknown`。
`agent_connection` はactiveかつ時刻が最近ならrecent、disconnected/never_connected/pendingまたは古い通信ならaged、
未対応の状態・矛盾した応答はunknownとする。`os_record` はOSレコードの時刻だけを判定する。
一方がrecentでも `freshness` をfreshに昇格させない。

| 条件 | 所見・statusの扱い |
|---|---|
| 追加機能が無効 | 既存動作を維持。追加通信なし |
| 情報取得成功、両観測値recent | 所見と元のstatusを維持。脆弱性結果の鮮度は未検証と表示 |
| aged/unknown、権限不足、無効応答、時間不足 | 所見を保持し、元がcompletedならpartialへ。元のpartial/errorは改善しない。原因を警告 |
| ManagerのID/名前が対象と矛盾 | Managerの補足情報を採用せずpartialと警告。Indexer側の端末照合を上書きしない |
| Indexer検索自体が失敗 | 既存のerrorを維持。追加のManager照会を行わない |
| 所見取得後、補足情報取得中にキャンセル | 所見を保持したpartialとして中断を明示。取得前のキャンセルは既存のerror |

OSレコードのaged警告には「OSレコードの時刻が古い。収集停止を示すものではない」と明記する。
0件は追加情報がrecentでも安全判定にしない。

## ページ送りとダッシュボード

ページごとの呼び出しで補足情報を取り直し、各ページに独立したchecked_atを付ける。
ページ群は原子的な同一時点のスナップショットではない。最新ページの接続情報で、古いページの所見が更新済みと見せない。
ページ集計では従来どおり同じカーソルの再取得を置き換え、statusは最悪値を維持する。
補足情報は対象ごとに、集計に残ったページの最も古いchecked_atと最も悪い観測状態を表示する。
補足情報がないページも含まれる場合は「一部未確認」とする。

ダッシュボードは「結果取得日時」「最終通信日時」「OSレコード日時」「脆弱性照合の完了日時は未確認」を区別する。
既定の要約履歴には接続先・JWT・生応答を追加しない。履歴側の新しい補足情報は、固定の状態と正規化済み時刻だけを
オプション項目として保存し、既存の履歴が読めることを維持する。詳細保存が無効でも、この最小メタデータは表示できる設計とする。
`freshness_evidence.index_observed_at` にIndexer結果取得日時も保存し、ダッシュボードでは集計対象ページの最も古い取得日時を示す。
従来の履歴の開始日時とは区別する。

## 検証計画と段階

1. 実環境での意味検証は4.14.9の対象001で実施済み。定期収集前後のOS・パッケージ時刻、最終通信、設定、収集ログを比較し、
   パッケージ時刻が更新されないことと、今回のOS時刻が完了時刻ではないことを記録した。他OS・他バージョンへの一般化はしない。
2. 専用RBACの検証を実施済み。対象001の読取が成功し、002・他ユーザーの明示参照・Manager設定の読取は403。
   対象001の有効設定とパッケージの読取も成功するため、OSだけの分離は未実現。再起動・登録/削除等は要求せず、
   実効ポリシーに書込みアクションがないことを確認した。無指定のユーザー一覧は200・0件で、403とは区別する。
3. 回帰テスト：無効時無通信、認証・TLS失敗、各HTTPエラー、アプリ内失敗、対象ID不一致、日時欠落・非ASCII制御文字・未来時刻、
   閾値ちょうど/1マイクロ秒超過、全体期限、ヘッダー前/本文停止のキャンセル、JWT非漏洩、0件、各所見保持、ページ再取得を確認する。
4. 実環境の専用読取アカウントで、成功・対象外拒否・認証/TLS失敗・閾値超過・共通期限・キャンセル・所見保持・
   ページ集計・要約履歴・ダッシュボードHTMLを確認済み。
   [受入試験記録](acceptance/wazuh-freshness-2026-10-19.json)を参照。既存設定・証明書・公開ポートは変更せず、一時的なTCP中継を使った。
   追加通信の有効化を含む常用設定への反映、実ブラウザー操作、Windows/Linux実機受入は別作業。
   実装時のAndroid・MCPを含む全322件は316件成功・Windows専用6件スキップ、npm接続15件成功。新機能の全OS CIは未実行。

完全な脆弱性鮮度の判定は第2段階とする。対象と収集世代に結び付いた完了証拠、照合に使った定義の版/日時、
Indexer反映の完了まで確認できる情報源が必要になる。今回のAPIだけで揃うとは仮定せず、それまでfreshという総合判定は追加しない。
