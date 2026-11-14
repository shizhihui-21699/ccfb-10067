# tlog — 制品签名透明日志

按 RFC 6962 Merkle 树实现的追加式透明日志,用于内部发版制品签名的可审计登记:任何一条签名记录入日志后,服务端无法在不留下证据的情况下篡改、回滚或分叉历史。

## 组成

| 组件 | 说明 |
|---|---|
| `tlog-server` | 日志服务器:追加记录、出包含/一致性证明、定期 Ed25519 签名树头(STH)、内置查询页面 |
| `tlog-verify` | 离线验证工具:验包含证明、验一致性证明、跟踪 STH,识别**篡改 / 回滚 / 分叉** |
| `tlog-bench` | 压测:百万条记录的追加吞吐与证明延迟 |

## 构建与测试

```sh
cargo build --release
cargo test
```

## 快速开始

```sh
# 启动服务(首次运行自动生成签名密钥 key / key.pub)
./target/release/tlog-server --dir ./data --addr 127.0.0.1:8080 --sign-every 1000

# 追加一条制品签名记录
curl -X POST localhost:8080/append \
  -d '{"data": "{\"artifact\":\"app-1.2.3.tar.gz\",\"sha256\":\"ab12…\",\"signer\":\"ci-bot\"}"}'
# => {"index":0,"leaf_hash":"…","tree_size":1}

# 查询页面
open http://localhost:8080/

# 拉取证明和签名树头,离线验证
curl localhost:8080/sth > sth.json
curl "localhost:8080/proof?index=0" > proof.json
./target/release/tlog-verify inclusion --proof proof.json --sth sth.json --pubkey data/key.pub
```

## API

| 端点 | 说明 |
|---|---|
| `POST /append` | body `{"data": "…"}` 或 `{"data_hex": "…"}` → `{index, leaf_hash, tree_size}` |
| `GET /record?index=N` | 记录内容 + 叶子哈希 |
| `GET /proof?index=N[&size=M]` | 包含证明(默认取最新 STH 覆盖的树大小) |
| `GET /consistency?first=A&second=B` | 两个树大小之间的一致性证明 |
| `GET /sth` / `GET /sth/all` | 最新 / 全部签名树头 |
| `POST /sign` | 立即对当前树头签名 |
| `GET /pubkey` | 验证公钥(hex) |

## 安全模型与攻击检测

- **哈希**:RFC 6962 §2.1,叶子 `SHA256(0x00‖data)`,内部节点 `SHA256(0x01‖L‖R)`,域分离防第二原像攻击。
- **签名树头(STH)**:Ed25519 签名 `(tree_size, root_hash, timestamp)`,每 `--sign-every` 条自动签一次,也可 `POST /sign` 手动签。客户端钉住公钥即可**离线验证**。
- **篡改**:`tlog-verify inclusion` 重算叶子哈希和 Merkle 路径,与 STH 根比对,任何记录/证明改动都会失败(exit 2)。
- **回滚**:`tlog-verify track` 在本地保存见过的最大 STH;服务端出示更小的树 → exit 3。
- **分叉**:同一 tree_size 出现两个不同根的合法签名头,或新旧 STH 间一致性证明无效 → exit 4。这要求日志的私钥也无法抵赖——两个签名头就是分叉的密码学证据。

```sh
# 持续监控:每次拿到新 STH 时
tlog-verify track --state ~/.tlog-state.json --sth new-sth.json --proof cons.json --pubkey key.pub
```

## 存储与断电安全

```
data/
  leaves.dat      追加写:u32 长度 + 记录原文
  level_00.dat…   各层 32 字节哈希(level L 有 ⌊size/2^L⌋ 个)
  commit(.tmp)    16 字节提交点:tree_size + leaves 长度
  sth.log         每行一个签名树头(JSON)
  key / key.pub   Ed25519 密钥对
```

每次 `commit`:先写并 fsync 所有数据文件,再写 `commit.tmp` → fsync → 原子 rename 为 `commit` → fsync 目录。崩溃后重启按提交点截断多写的尾部,树永远处于一致状态;未提交的最后一批记录丢失,但已提交的历史绝不受损。`sth.log` 启动时校验,凡是超出提交点或签名无效的条目会被清掉。

1M 条约占 200MB 磁盘(记录原文 + 2N 个哈希),内存占用 O(1)(仅追加缓冲;偏移索引约 8MB)。

## 压测

```sh
./target/release/tlog-bench --dir /tmp/tlog-bench --n 1000000 --batch 1000
```

输出:逐条持久化追加延迟、批量追加吞吐、包含/一致性证明生成延迟、客户端验证耗时、重启恢复时间、磁盘占用。
