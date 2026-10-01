# keystore/ — 仓内置的开发签名 key

`ghostlock-dev.jks`（PKCS12，alias `ghostlock`，store/key 口令均为 `ghostlock-dev`，RSA 4096，有效期 30 年）
**是刻意提交进仓库的**，用来替换 AGP 每轮随机生成的 debug key。

## 为什么要有它

CI（`.github/workflows/build.yml`）在没有签名 secrets 的情况下走 debug 签名，而 AGP 在**每个 runner 上
新生成** debug keystore ⇒ 每次构建签名都不同 ⇒ 覆盖安装 `adb install -r` 直接
`INSTALL_FAILED_UPDATE_INCOMPATIBLE`，必须先卸载；而**卸载会清掉 app 私有目录**，也就是：

* `adbkey.pk8` / `adbkey.pub.der` / `adbkey.cert.der`（本 app 的配对密钥）；
* `ghostlock-wireless` 里的"已配对"记录。

结果就是：**每装一个新构建都要重新走一次无线调试配对**。换成仓内固定 key 后，构建之间
`adb install -r` 直接可用，配对与密钥都保留。

## 优先级与覆盖方式

`app/build.gradle.kts` 的解析顺序：

1. `local.properties` 的 `KEYSTORE_PATH` / `KEYSTORE_PASS` / `KEY_ALIAS` / `KEY_PASSWORD`；
2. 同名环境变量（CI 从 repository secrets 注入：`SIGNING_KEY`(base64) / `KEY_STORE_PASSWORD` / `ALIAS` / `KEY_PASSWORD`）；
3. 本目录的 `ghostlock-dev.jks`。

也就是说：**如果以后把 secrets 配上，secrets 优先**，这个仓内 key 自动退为本地/PR 构建用的兜底。

## 安全提示（请知情）

* 仓库是 **public**，所以这把私钥是**公开的**：任何拿到它的人都能签出"更新包"，装到已安装本 app 的设备上
  （Android 只比对签名证书是否一致）。对本项目当前的用法（自用、内测、CI 产物手动安装）可以接受；
  **一旦要上应用商店或对外分发，请立刻换掉它**，并把新的 key 放 secrets 而不是仓库。
* 若要走更干净的路：把 `ghostlock-dev.jks` base64 后填进 secrets `SIGNING_KEY`，其余三个值填进对应 secrets，
  本文件与 `ghostlock-dev.jks` 即可从仓库删除（Gradle 会自动优先用 secrets）。
