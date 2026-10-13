# リリース手順（npm）

npm パッケージ `personal-pc-scanner-mcp` は、GitHub のリリースを公開すると
ワークフロー「Publish to npm」（`.github/workflows/publish-npm.yml`）がステージド公開として提出します。
npmjs.com で所有者が 2FA で承認するまで、利用者には届きません。

- **認証**：信頼された公開元（trusted publishing、OIDC）。npm のトークンを GitHub に保存しません。
- **出自の証明**：公開リポジトリからの公開なので、npm がどのコミットとワークフローから作ったか（provenance）を記録します。
  ステージド公開で付くかどうかは npm の説明に明記がないため、最初の公開後に確認します（下の「公開後の確認」）。
- **ジョブの分離**：テストのジョブは PyPI からパッケージを導入するため、公開用のトークンを要求する権限（`id-token`）を与えていません。
  公開のジョブは何も導入せず、`npm stage publish` だけを実行します。

## 最初に一度だけ行う設定（所有者）

npmjs.com でパッケージの設定を開き、次を行います。

1. **Trusted publishing** に GitHub Actions を追加する
   - Organization or user：`tedorigawa001`
   - Repository：`PersonalPCScanner-MCP`
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

## 公開後の確認

```sh
npm view personal-pc-scanner-mcp@<バージョン> dist.integrity dist.attestations
```

- `dist.attestations` があれば provenance が付いています。npmjs.com のパッケージのページにも表示されます。
- 公開物の `dist.integrity` が、リリースしたコミットで `npm pack --json` して得た `integrity` と一致することを確かめます。
- リポジトリの外で `npx -y personal-pc-scanner-mcp@<バージョン> setup` を実行し、導入できることを確かめます。
