# GHTM - GitHub Token Manager
GitHubの個人アクセストークンを管理するCLIツールです。

## ビルド
```bash
git clone https://github.com/ragmilk/ghtm.git
cd ghtm
cargo build --release
```

## 使用方法
### 1. 初期設定
初回使用時にマスターパスワードを設定する必要があります。
```bash
ghtm init
```

### 2. トークンの追加
```bash
ghtm add
```

### 3. トークンの一覧を表示
```bash
ghtm list
```

### 4. トークンの読み込み
```bash
ghtm load example
```
トークン名を省略すると、前回使用したトークンを自動的にロードします。
前回使用したトークンがない場合や期限切れの場合は、対話的に選択できます。
```bash
ghtm load
```

### 5. トークンの削除
```bash
ghtm remove example
ghtm rm example
```
