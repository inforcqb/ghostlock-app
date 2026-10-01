# keystore/ — 签名 key 已经**不在这个公开仓库里**了

签名材料（`ghostlock-dev.jks`，PKCS12，alias `ghostlock`，store/key 口令均为 `ghostlock-dev`，
RSA 4096，有效期 30 年）现在放在**私有仓库**：

```
inforcqb/ghostlock-keys      （private）
  ├── ghostlock-dev.jks
  └── README.md              ← 口令、轮换步骤、历史泄露说明
```

公开仓库的 CI 通过一把**只读 deploy key**（私钥存在本仓库 secret `KEYSTORE_DEPLOY_KEY`）
在构建时 clone 它，把 `ghostlock-dev.jks` 落到工作区根目录的 `keystore.jks`
（`KEYSTORE_PATH=../keystore.jks`），并用文档里的口令/alias 签名。

## 为什么不能放公开仓库

固定一把 key 是必须的：AGP 在每个 CI runner 上**新生成** debug keystore ⇒ 每次构建签名都不同 ⇒
`adb install -r` 报 `INSTALL_FAILED_UPDATE_INCOMPATIBLE`，必须先卸载；而卸载会清掉 app 私有目录
（配对密钥 + "已配对"记录）⇒ 每装一个新构建都要重新配对。

但公开仓库里的私钥等于**公开的私钥**：任何拿到它的人都能签出能覆盖安装的"更新包"。
所以它被移到私有仓库，公开树只保留"怎么取"的说明。

## 签名 key 的解析顺序（`app/build.gradle.kts`）

1. `local.properties` 的 `KEYSTORE_PATH` / `KEYSTORE_PASS` / `KEY_ALIAS` / `KEY_PASSWORD`；
2. 同名环境变量（CI 里由 secrets 注入：`SIGNING_KEY`(base64) / `KEY_STORE_PASSWORD` / `ALIAS` / `KEY_PASSWORD`）；
3. 都没有时：**没有兜底了** —— 公开树里那份已删除。

CI 的两个相关步骤：

* `Decode Android signing key`：`SIGNING_KEY` 配了就解出 keystore.jks（优先级最高）；
* `Fetch the signing keystore from the private repo`：`SIGNING_KEY` 没配时从私有仓库取，
  并打印 sha256（`a1b450c0…d4f4c`，与历次发布一致）；
* `Require the fetched keystore`：非 PR 构建若 `keystore.jks` 为空/缺失就**直接失败** ——
  用一个随机 key 签出来的 release 会让所有已装设备都得先卸载，比构建失败糟糕得多。

构建日志里会有一行 `signing: keystore=… fallback=…`，用来确认到底用了哪把 key。

## 本地构建怎么办

* 想用**同一把 key**：`git clone git@github.com:inforcqb/ghostlock-keys.git`，然后
  `local.properties` 里写 `KEYSTORE_PATH=/绝对路径/ghostlock-dev.jks`、`KEYSTORE_PASS=ghostlock-dev`、
  `KEY_ALIAS=ghostlock`、`KEY_PASSWORD=ghostlock-dev`；
* 只用 debug 签名：什么都不配即可（debug 构建本来就用 debug key，与 release 无关）。

## 历史与轮换（请知情）

* 这把 key **在 2026-10-01 之前提交在公开仓库里**（`keystore/ghostlock-dev.jks`），所以它已经泄露过；
  从树里删掉只是停止继续暴露，**git 历史里仍然有它**。
* 要彻底作废：换一把新 key（新口令/别名，放私有仓库），代价是设备必须**卸载重装一次**
  （签名变了），卸载会丢无线调试配对，需要重新配对。
* 在那之前，任何来源可疑的 GhostLock 更新包都应当视为可以用泄露 key 伪造的。
