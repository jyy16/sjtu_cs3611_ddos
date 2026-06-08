# Demo Command Runbook

本文档集中整理当前项目演示、组内自测、Redis 存储验证和后续开发常用命令。除特别说明外，所有命令都在项目根目录执行。

## 0. 环境准备

推荐在 Linux/WSL 环境运行完整 demo，因为脚本会用到 `bash`、`tcpdump`、`iptables`/`nftables`、`sudo` 等工具。

```bash
cd /path/to/sjtu_cs3611_ddos
python3 -m venv .venv
.venv/bin/python -m pip install -r models/requirements.txt
cp scripts/demo.env.example scripts/demo.env
```

如果使用虚拟环境里的 Python，确认 `scripts/demo.env` 中有：

```bash
PYTHON=.venv/bin/python
```

## 1. Redis 存储模式

快速本地跑通可以保持：

```bash
STORAGE_BACKEND=none
```

最终验收或报告截图建议启用 Redis：

```bash
docker run --rm --name cs3611-redis -p 6379:6379 redis:7
```

另开一个终端检查 Redis：

```bash
redis-cli -u redis://127.0.0.1:6379/0 ping
```

然后修改 `scripts/demo.env`：

```bash
STORAGE_BACKEND=redis
REDIS_URL=redis://127.0.0.1:6379/0
STORAGE_KEY_PREFIX=cs3611:ddos
STORAGE_FAIL_OPEN=0
```

`STORAGE_FAIL_OPEN=0` 表示 Redis 不可用时直接失败，适合最终验收。开发调试时可以临时设成 `1`。

## 2. 一键演示

先做接口和依赖预检：

```bash
bash scripts/run_demo.sh --check-only
```

查看总控脚本将执行哪些命令：

```bash
bash scripts/run_demo.sh --dry-run
```

正式运行完整 demo：

```bash
bash scripts/run_demo.sh
```

使用固定 run id，方便报告引用和复现实验：

```bash
bash scripts/run_demo.sh --run-id report_demo_01
```

如果要在演示前重新训练模型：

```bash
bash scripts/run_demo.sh --train --run-id train_demo_01
```

Mininet 或外部 victim 服务场景：

```bash
START_TARGET=0 TARGET_IP=10.0.0.2 TARGET_PORT=80 TARGET_URL=http://10.0.0.2/ CAPTURE_IFACE=h1-eth0 bash scripts/run_demo.sh --run-id mininet_demo_01
```

### 2.1 实时攻防演示（新增）

`scripts/run_demo.sh` 保留“攻击前抓包 -> 离线推理封禁 -> 防御后再攻击”的前后对比流程。若要演示“混合攻击进行时，后台同步进行 AI 推理与自动封禁”，使用新的实时脚本：

```bash
bash scripts/run_realtime_demo.sh --check-only
```

查看实时脚本将执行哪些命令：

```bash
bash scripts/run_realtime_demo.sh --dry-run
```

正式运行实时攻防演示：

```bash
bash scripts/run_realtime_demo.sh --run-id realtime_demo_01
```

实时脚本的关键区别是：`attacks/run_mixed_attack.sh` 在前台持续运行，同时后台启动 `realtime_defense_loop`，按窗口执行“抓包 -> 特征提取 -> 模型推理 -> apply_decision 自动封禁”。这不是先攻击后封禁。

调整后台实时检测窗口长度，例如每 3 秒推理一次：

```bash
REALTIME_WINDOW_SECONDS=3 bash scripts/run_realtime_demo.sh --run-id realtime_demo_02
```

如果模型加载或 iptables 封禁比较慢，把实时攻击时长拉长，确保封禁动作发生在攻击仍在进行时：

```bash
REALTIME_ATTACK_SECONDS=180 bash scripts/run_realtime_demo.sh --run-id realtime_demo_03
```

默认实时脚本不预先安装基础限速规则，更容易展示“模型识别后才自动封禁”。如果希望同时打开基础 SYN/HTTP/UDP 防御规则：

```bash
bash scripts/run_realtime_demo.sh --baseline --run-id realtime_baseline_01
```

Mininet 或外部 victim 服务的实时演示：

```bash
START_TARGET=0 TARGET_IP=10.0.0.2 TARGET_PORT=80 TARGET_URL=http://10.0.0.2/ CAPTURE_IFACE=h1-eth0 bash scripts/run_realtime_demo.sh --run-id mininet_realtime_01
```

## 3. 组内接口自测

攻击组：

```bash
bash scripts/check_group_contract.sh attack
```

防御组：

```bash
bash scripts/check_group_contract.sh defense
```

模型组：

```bash
bash scripts/check_group_contract.sh model
```

全部自测建议按这个顺序跑：

```bash
bash scripts/check_group_contract.sh attack
bash scripts/check_group_contract.sh defense
bash scripts/check_group_contract.sh model
bash scripts/run_demo.sh --check-only
```

## 4. 单模块调试命令

### 4.1 启动 victim HTTP 服务

```bash
.venv/bin/python -m http.server 8080 --bind 127.0.0.1 --directory demo_site
```

检查服务可访问：

```bash
curl -fsS --max-time 5 http://127.0.0.1:8080/
```

### 4.2 攻击流量脚本

正常流量：

```bash
.venv/bin/python attacks/normal_traffic.py \
  --target-url http://127.0.0.1:8080/ \
  --duration 10 \
  --rate 5 \
  --output data/logs/demo/normal_traffic.log
```

SYN Flood：

```bash
.venv/bin/python attacks/syn_flood.py \
  --target-ip 127.0.0.1 \
  --target-port 8080 \
  --duration 20 \
  --rate 200 \
  --output data/logs/demo/syn_flood.log
```

HTTP Flood：

```bash
.venv/bin/python attacks/http_flood.py \
  --target-url http://127.0.0.1:8080/ \
  --duration 20 \
  --rate 80 \
  --method GET \
  --output data/logs/demo/http_flood.log
```

UDP reflection simulation：

```bash
.venv/bin/python attacks/udp_reflection_sim.py \
  --target-ip 127.0.0.1 \
  --target-port 8080 \
  --duration 20 \
  --rate 100 \
  --output data/logs/demo/udp_reflection.log
```

混合攻击入口：

```bash
bash attacks/run_mixed_attack.sh \
  --target-ip 127.0.0.1 \
  --target-port 8080 \
  --target-url http://127.0.0.1:8080/ \
  --duration 20 \
  --syn-rate 200 \
  --http-rate 80 \
  --udp-rate 100 \
  --output-dir data/logs/demo
```

### 4.3 抓包与特征提取

手动抓包：

```bash
sudo tcpdump -i any -nn -w data/pcap/demo/attack_before_defense.pcap "host 127.0.0.1"
```

从 PCAP 提取特征：

```bash
.venv/bin/python features/extract_features.py \
  --input data/pcap/demo/attack_before_defense.pcap \
  --output data/features/demo/attack_before_defense.csv \
  --label attack \
  --attack-type mixed_attack \
  --target-ip 127.0.0.1 \
  --window-size 1
```

### 4.4 模型训练与推理

训练 MLP：

```bash
.venv/bin/python models/train_mlp.py \
  --input data/features/train.csv \
  --output models/saved/model.pth \
  --metrics-out data/logs/demo/train_metrics.json
```

模型推理生成防御决策：

```bash
.venv/bin/python models/infer.py \
  --input data/features/demo/attack_before_defense.csv \
  --model models/saved/model.pth \
  --output data/logs/demo/decision.json \
  --threshold 0.80
```

### 4.5 防御规则与自动封禁

清理本项目规则：

```bash
bash defense/unblock_all.sh --project-tag cs3611-ddos
```

启用基础防御规则：

```bash
bash defense/iptables_rules.sh \
  --target-port 8080 \
  --syn-rate 50 \
  --http-rate 120 \
  --project-tag cs3611-ddos
```

查看当前规则：

```bash
bash defense/show_rules.sh --project-tag cs3611-ddos
```

根据模型输出自动执行封禁或限速：

```bash
.venv/bin/python defense/apply_decision.py \
  --decision data/logs/demo/decision.json \
  --threshold 0.80 \
  --block-script defense/block_ip.sh \
  --project-tag cs3611-ddos
```

手动封禁单个私有源 IP：

```bash
bash defense/block_ip.sh \
  --ip 10.0.0.9 \
  --reason manual_test_block \
  --ttl 300 \
  --project-tag cs3611-ddos
```

## 5. 结果文件与报告材料

完整 demo 结束后，材料默认在：

```text
data/pcap/<run_id>/
data/features/<run_id>/
data/logs/<run_id>/
```

常用检查命令：

```bash
ls -lh data/pcap/<run_id>/
ls -lh data/features/<run_id>/
ls -lh data/logs/<run_id>/
cat data/logs/<run_id>/decision_<run_id>.json
cat data/logs/<run_id>/train_metrics_<run_id>.json
```

生成离线 HTML 可视化页面：

```bash
.venv/bin/python scripts/visualize_demo.py --run-id <run_id>
```

指定输出位置：

```bash
.venv/bin/python scripts/visualize_demo.py \
  --run-id <run_id> \
  --output data/logs/<run_id>/demo_visualization_<run_id>.html \
  --title "Project 9 DDoS Defense Demo"
```

生成实时攻防 HTML 可视化页面：

```bash
.venv/bin/python scripts/visualize_realtime_demo.py --run-id <run_id>
```

指定实时可视化输出位置：

```bash
.venv/bin/python scripts/visualize_realtime_demo.py \
  --run-id <run_id> \
  --output data/logs/<run_id>/realtime_visualization_<run_id>.html \
  --title "Project 9 Realtime DDoS Defense Demo"
```

## 6. Redis 数据检查

查看所有 demo run：

```bash
redis-cli SMEMBERS cs3611:ddos:runs
```

查看某次 run 的元信息：

```bash
redis-cli HGETALL cs3611:ddos:run:<run_id>
```

查看特征流：

```bash
redis-cli XRANGE cs3611:ddos:run:<run_id>:features:normal_<run_id> - + COUNT 5
redis-cli XRANGE cs3611:ddos:run:<run_id>:features:attack_before_defense_<run_id> - + COUNT 5
redis-cli XRANGE cs3611:ddos:run:<run_id>:features:attack_after_defense_<run_id> - + COUNT 5
```

查看模型决策：

```bash
redis-cli HGETALL cs3611:ddos:run:<run_id>:decision:decision_<run_id>
redis-cli XRANGE cs3611:ddos:run:<run_id>:decision:decision_<run_id>:items - + COUNT 10
```

查看防御动作：

```bash
redis-cli XRANGE cs3611:ddos:run:<run_id>:defense_actions - + COUNT 10
```

查看 `defense/block_ip.sh` 实际写入的自动封禁日志备份：

```bash
redis-cli XRANGE cs3611:ddos:run:<run_id>:defense_block_log - + COUNT 10
redis-cli HGETALL cs3611:ddos:run:<run_id>:defense_block_log_summary:defense_blocks_<run_id>
```

## 7. 测试与验证

运行受影响的轻量测试：

```bash
.venv/bin/python -m pytest models/tests/test_feature_extraction.py models/tests/test_redis_storage.py -q
```

运行全部模型测试：

```bash
.venv/bin/python -m pytest models/tests
```

脚本语法检查：

```bash
bash -n scripts/run_demo.sh
bash -n scripts/run_realtime_demo.sh
bash -n scripts/check_group_contract.sh
.venv/bin/python -m py_compile storage/redis_store.py features/extract_features.py models/infer.py defense/apply_decision.py scripts/visualize_realtime_demo.py
```

## 8. 清理命令

清理防御规则：

```bash
bash defense/unblock_all.sh --project-tag cs3611-ddos
```

停止 Docker Redis：

```bash
docker stop cs3611-redis
```

删除某次 Redis run 数据时，先列出 key：

```bash
redis-cli --scan --pattern "cs3611:ddos:run:<run_id>*"
```

确认无误后删除：

```bash
redis-cli --scan --pattern "cs3611:ddos:run:<run_id>*" | xargs -r redis-cli DEL
```

## 9. 常见问题

如果 `run_demo.sh --check-only` 报 Redis 依赖缺失：

```bash
.venv/bin/python -m pip install -r models/requirements.txt
```

如果 Redis 没启动：

```bash
redis-cli -u redis://127.0.0.1:6379/0 ping
```

如果只是临时开发，不想让 Redis 阻塞 demo：

```bash
STORAGE_BACKEND=redis STORAGE_FAIL_OPEN=1 bash scripts/run_demo.sh --check-only
```

如果本地抓不到 loopback 流量，优先使用：

```bash
CAPTURE_IFACE=any bash scripts/run_demo.sh --run-id any_capture_test
```

如果目标服务已经手动启动：

```bash
START_TARGET=0 bash scripts/run_demo.sh --run-id external_target_test
```
