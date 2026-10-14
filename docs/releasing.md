# リリース手順（npm）

npm パッケージ `personal-device-scanner-mcp`（0.1.2 までの旧名は `personal-pc-scanner-mcp`）は、GitHub のリリースを公開すると
ワークフロー「Publish to npm」（`.github/workflows/publish-npm.yml`）がステージド公開として提出します。
npmjs.com で所有者が 2FA で承認するまで、利用者には届きません。

- **認証**：信頼された公開元（trusted publishing、OIDC）。npm のトークンを GitHub に保存しません。
- **出自の証明**：公開リポジトリからの公開なので、npm がどのコミットとワークフローから作ったか（provenance）を記録します。
  ステージド公開でも付くことを 0.1.1 で確認しました（SLSA provenance v1、Sigstore の透明性ログに記録）。
- **ジョブの分離**：テストのジョブは PyPI からパッケージを導入するため、公開用のトークンを要求する権限（`id-token`）を与えていません。
  公開のジョブは何も導入せず、`npm stage publish` だけを実行します。

## 最初に一度だけ行う設定（所有者）

npmjs.com でパッケージの設定を開き、次を行います。

1. **Trusted publishing** に GitHub Actions を追加する
   - Organization or user：`tedorigawa001`
   - Repository：`PersonalDeviceScanner-MCP`
   - Workflow filename：`publish-npm.yml`
   - Environment name：空欄
   - 許可する操作：`npm stage publish` のみ（`npm publish` は許可しない）
2. **Publishing access** で「Require two-factor authentication and disallow tokens」を選ぶ
   （トークンによる公開を禁止します。信頼された公開元からのステージド公開は影響を受けません）

npm は保存時に設定を検証しないため、誤りは最初の公開のときに分かります。
`package.json` の `repository.url` は、このリポジトリの URL と完全に一致している必要があります。

## リリースのたびに行うこと

1. バージョンを3か所で同じ値に上げる：`package.json`、`pyproject.toml`、`pc_scanner/__init__.py`
   （一致しないと npm のテストが失敗します）
2. コミットして push し、CI がすべて成功することを確認する
3. タグ `v<バージョン>` で GitHub のリリースを公開する。例：

   ```sh
   gh release create v0.1.1 --title "v0.1.1" --notes "変更点"
   ```

4. ワークフロー「Publish to npm」が、タグとバージョンの一致を確かめ、テストしてからステージド公開を提出する
5. npmjs.com の「Staged Packages」タブで内容を確認し、2FA で承認する（CLI なら `npm stage approve <stage-id>`）

## うまくいかないとき

- **`npm error code E401` / `Unable to authenticate, your authentication token seems to be invalid.`**：
  信頼された公開元（OIDC）での認証が npm に拒否され、トークンでの認証に切り替わって失敗しています。
  npmjs.com の Trusted publishing の設定（上の「最初に一度だけ行う設定」の値、とくに Environment name が空欄か）を確認してください。
  直したら、新しいリリースは作らずに、失敗したジョブだけを再実行します：`gh run rerun <run-id> --failed`

## 公開後の確認

```sh
npm view personal-device-scanner-mcp@<バージョン> dist.integrity dist.attestations
```

- `dist.attestations` があれば provenance が付いています。npmjs.com のパッケージのページにも表示されます。
- 空のフォルダーで `npm install personal-device-scanner-mcp@<バージョン>` してから `npm audit signatures` を実行し、
  「verified attestation」と表示されることを確かめます。
- 公開物の `dist.integrity` が、リリースしたコミットで `npm pack --json` して得た `integrity` と一致することを確かめます。
- リポジトリの外で `npx -y personal-device-scanner-mcp@<バージョン> setup` を実行し、導入できることを確かめます。
