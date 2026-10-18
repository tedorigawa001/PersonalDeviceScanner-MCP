# Security policy / セキュリティポリシー

[English](#english) | [日本語](#日本語)

## English

### Supported versions

| Version | Security fixes |
|---|---|
| The latest release ([Releases](https://github.com/tedorigawa001/PersonalDeviceScanner-MCP/releases)) | Yes |
| Earlier releases | No: update to the latest release |
| `personal-pc-scanner-mcp` (the old npm name, removed on 2026-10-15) | No |

Fixes are published as a new release. With `npx`, change the version in your client's configuration to the new one
(see "Using npx" in the [README](README.md)).

### Reporting a vulnerability

Please **do not** report a vulnerability in a public issue, pull request or discussion.

Report it privately through GitHub instead: open the repository's **Security** tab and choose
**Report a vulnerability** ([direct link](https://github.com/tedorigawa001/PersonalDeviceScanner-MCP/security/advisories/new)).
Only the maintainer can read it.

Please include:

- The version, and how it was installed (`npx`, or `pip` from the source)
- The OS, and the engines involved (osquery, ClamAV, Wazuh, adb) with their versions
- Steps to reproduce, or a proof of concept, and the impact you expect

Before sending, **remove personal data**: results, the scan history and logs can hold file, app, host and user names,
and Android serials. Use made-up values where you can, and never send a password or token (the Wazuh credentials, for
example). Test only on your own devices and accounts: do not scan or probe other people's PCs, phones or routers, or the
services this tool reads (GitHub, Google, MyJVN).

### What to expect

This project is maintained by one person, so these are targets, not guarantees:

- A reply within **7 days**.
- Within **30 days**, an assessment and either a fix or a plan.
- A confirmed issue is reproduced, fixed with a test, and released as a new version. A GitHub security advisory is
  published with the release, crediting you if you wish.

Please keep the details private until the fix is released. If a fix is not possible, we will agree on when to disclose.

### Scope

In scope is the code in this repository: the Python package `pc_scanner` (the MCP server and the CLI), the npm launcher,
the release workflows, and the published npm package `personal-device-scanner-mcp`. For example:

- The AI client, or text it can influence (file, app and package names, engine output, answers from Wazuh, MyJVN,
  GitHub or Google), makes the scanner do more than documented: run other commands or SQL, read outside the authorized
  folders, change or delete files, reach other hosts, or inspect a device that is not registered.
- A result hides findings, or makes a PC or device look safer than it is.
- The owner's data reaches the AI client or the network beyond what the [README](README.md) describes.
- Another user on the same PC uses the scan history, dashboard, cache or lock files to read or write the owner's files.
- The npm package, the locked dependencies or the SBOM do not match the source of the release.

Out of scope:

- Vulnerabilities in osquery, ClamAV, Wazuh, adb, the AI client, or the MyJVN, GitHub and Google services: please
  report them to those projects.
- What the engines do not detect (a missed malware sample or CVE), and the other limitations in the README.
- Anything that needs code already running as the owner or an administrator, or a change to the owner's configuration
  file: the owner and the configuration are trusted (see "Operating assumptions" in the README).
- An AI client running tools without asking: that is the client's setting (see "Safety design" in the README).

### Verifying a release

The npm package is published from GitHub Actions with a signed provenance statement (SLSA v1), after the maintainer
approves it with two-factor authentication. After installing, `npm audit signatures` should report a verified
attestation. The SBOM (CycloneDX) is in [sbom/](sbom/) and [profiles/](profiles/). The release steps and checks are in
[docs/releasing.md](docs/releasing.md) (in Japanese).

## 日本語

### サポートするバージョン

| バージョン | セキュリティの修正 |
|---|---|
| 最新のリリース（[Releases](https://github.com/tedorigawa001/PersonalDeviceScanner-MCP/releases)） | あり |
| それより前のリリース | なし：最新のリリースに更新してください |
| `personal-pc-scanner-mcp`（2026-10-15 に削除した npm の旧名） | なし |

修正は新しいリリースとして公開します。`npx` で使っている場合は、クライアントの設定のバージョンを新しいものに変えてください
（[README](README.ja.md) の「npx で使う場合」）。

### 脆弱性の報告

脆弱性は、公開の Issue・プルリクエスト・Discussions に**書かないでください**。

代わりに GitHub の非公開の報告を使ってください。リポジトリの **Security** タブで **Report a vulnerability** を選びます
（[直接のリンク](https://github.com/tedorigawa001/PersonalDeviceScanner-MCP/security/advisories/new)）。読めるのは管理者だけです。

次を書いてください。

- バージョンと導入方法（`npx`、またはソースからの `pip`）
- OS と、関係するエンジン（osquery・ClamAV・Wazuh・adb）とそのバージョン
- 再現の手順か概念実証と、想定される影響

送る前に**個人の情報を取り除いてください**。結果・スキャン履歴・ログには、ファイル・アプリ・ホスト・ユーザーの名前や
Android のシリアル番号が含まれることがあります。できるだけ架空の値を使い、パスワードやトークン（Wazuh の認証情報など）は
送らないでください。試すのは自分の端末とアカウントだけにし、他人の PC・スマートフォン・ルーターや、このツールが読むサービス
（GitHub・Google・MyJVN）をスキャンしたり探ったりしないでください。

### 対応の目安

管理者が1人のプロジェクトのため、次は目標であり、保証ではありません。

- **7日以内**に返信します。
- **30日以内**に評価し、修正か対応の計画を示します。
- 確認できた問題は、再現してからテストとともに修正し、新しいバージョンとして公開します。公開と同時に GitHub の
  セキュリティアドバイザリを出し、希望があれば報告者として名前を記載します。

修正を公開するまでは、詳細を公開しないでください。修正できない場合は、公開の時期を相談して決めます。

### 対象

対象は、このリポジトリのコードです。Python パッケージ `pc_scanner`（MCP サーバーと CLI）、npm のランチャー、リリースの
ワークフロー、公開した npm パッケージ `personal-device-scanner-mcp` を含みます。たとえば次のようなものです。

- AI クライアントや、それが影響できる文字列（ファイル・アプリ・パッケージの名前、エンジンの出力、Wazuh・MyJVN・GitHub・
  Google の応答）によって、スキャナーが説明以上のことをする：ほかのコマンドや SQL の実行、許可したフォルダーの外の読み取り、
  ファイルの変更や削除、ほかの接続先への通信、登録していない端末の点検
- 結果が所見を隠したり、PC や端末を実際より安全に見せたりする
- 所有者の情報が、[README](README.ja.md) の説明を超えて AI クライアントやネットワークに渡る
- 同じ PC のほかのユーザーが、スキャン履歴・ダッシュボード・キャッシュ・ロック用のファイルを使って、所有者のファイルを
  読み書きできる
- npm パッケージ・ロックした依存パッケージ・SBOM が、そのリリースのソースと一致しない

対象外：

- osquery・ClamAV・Wazuh・adb・AI クライアント、MyJVN・GitHub・Google のサービスの脆弱性。それぞれのプロジェクトに
  報告してください。
- エンジンが検出できないもの（見逃したマルウェアや CVE）と、README のそのほかの制限事項
- すでに所有者や管理者として動いているコード、または所有者の設定ファイルの変更が必要なもの。所有者と設定は信頼する前提です
  （README の「動作上の前提」）。
- AI クライアントが確認なしにツールを実行すること。クライアントの設定です（README の「安全のための設計」）。

### リリースの確かめ方

npm パッケージは、管理者が2要素認証で承認してから、GitHub Actions から署名つきの出自の証明（provenance、SLSA v1）とともに
公開します。導入後に `npm audit signatures` を実行すると、検証済みの証明（verified attestation）と表示されます。
SBOM（CycloneDX）は [sbom/](sbom/) と [profiles/](profiles/) にあります。リリースの手順と確認は
[docs/releasing.md](docs/releasing.md) にあります。
