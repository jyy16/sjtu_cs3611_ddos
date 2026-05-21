# Project 9 Final Demo Command Requirements

这份文档就是三组的“接口合同”。最后演示时，整合负责人只运行：

```bash
bash scripts/run_demo.sh
```

所以各组必须实现下面这些文件和命令。只要命令、参数、输出格式一致，内部实现可以自由选择 Python、Bash、Scapy、hping3、iptables、nftables、PyTorch 或 scikit-learn。

## 0. 统一安全要求

所有攻击脚本必须拒绝公网目标，只允许：

```text
127.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

每个脚本都必须支持：

```bash
--help
```

成功时退出码为 `0`，失败时退出码非 `0`，并在终端输出清楚的错误原因。

每组完成后，可以先运行自己的接口检查：

```bash
bash scripts/check_group_contract.sh attack
bash scripts/check_group_contract.sh defense
bash scripts/check_group_contract.sh model
```

## 1. 最终演示入口

整合负责人最后运行：

```bash
cp scripts/demo.env.example scripts/demo.env
bash scripts/run_demo.sh --check-only
bash scripts/run_demo.sh
```

如果是在 Mininet 中演示，可能使用：

```bash
START_TARGET=0 TARGET_IP=10.0.0.2 TARGET_PORT=80 TARGET_URL=http://10.0.0.2/ CAPTURE_IFACE=h1-eth0 bash scripts/run_demo.sh
```

总控脚本会依次执行：

```text
1. 检查所有组的脚本是否存在
2. 启动或检查 victim HTTP 服务
3. 清空旧防御规则
4. 生成正常流量并抓包
5. 生成混合攻击流量并抓包
6. 从 PCAP 提取特征
7. 调用模型推理，输出攻击判断 JSON
8. 启用防火墙规则，并按模型判断封禁攻击 IP
9. 再次运行同样攻击，展示防御前后差异
```

## 2. 攻击组必须实现的命令

攻击组负责目录：

```text
attacks/
```

必须交付文件：

```text
attacks/normal_traffic.py
attacks/syn_flood.py
attacks/http_flood.py
attacks/udp_reflection_sim.py
attacks/run_mixed_attack.sh
```

### 2.1 正常流量

总控脚本会调用：

```bash
python3 attacks/normal_traffic.py \
  --target-url http://127.0.0.1:8080/ \
  --duration 10 \
  --rate 5 \
  --output data/logs/demo/normal_traffic.log
```

参数含义：

```text
--target-url  目标 HTTP URL
--duration    持续时间，单位秒
--rate        每秒请求数
--output      请求日志输出路径
```

日志至少包含：

```text
timestamp,target_url,status_code,latency_ms,error
```

### 2.2 SYN Flood

攻击组内部脚本必须支持：

```bash
python3 attacks/syn_flood.py \
  --target-ip 127.0.0.1 \
  --target-port 8080 \
  --duration 20 \
  --rate 200 \
  --output data/logs/demo/syn_flood.log
```

参数含义：

```text
--target-ip    目标 IP，仅允许本地或私有网段
--target-port  目标端口
--duration     持续时间，单位秒
--rate         每秒发包数或请求数
--output       攻击日志输出路径
```

### 2.3 HTTP Flood

攻击组内部脚本必须支持：

```bash
python3 attacks/http_flood.py \
  --target-url http://127.0.0.1:8080/ \
  --duration 20 \
  --rate 80 \
  --method GET \
  --output data/logs/demo/http_flood.log
```

### 2.4 UDP 反射/放大模拟

注意：这里只能模拟实验环境内的 UDP 放大行为，不能访问真实 DNS/NTP 服务器。

攻击组内部脚本必须支持：

```bash
python3 attacks/udp_reflection_sim.py \
  --target-ip 127.0.0.1 \
  --target-port 8080 \
  --duration 20 \
  --rate 100 \
  --output data/logs/demo/udp_reflection.log
```

### 2.5 混合攻击入口

总控脚本实际会调用这个统一入口：

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

`run_mixed_attack.sh` 内部应同时或依次调用：

```text
attacks/syn_flood.py
attacks/http_flood.py
attacks/udp_reflection_sim.py
```

建议实现为并发运行 SYN Flood 和 HTTP Flood，UDP 模拟可以按环境情况开启。脚本结束前必须等待所有子进程退出，避免演示结束后攻击进程还在后台运行。

攻击组验收标准：

```text
1. normal_traffic.py 能稳定产生正常访问日志
2. run_mixed_attack.sh 能让 tcpdump/Wireshark 看到明显 PPS 上升
3. 所有攻击脚本都会拒绝公网 IP
4. 输出日志能说明攻击参数、开始时间、结束时间、错误信息
```

## 3. 防御组必须实现的命令

防御组负责目录：

```text
defense/
```

必须交付文件：

```text
defense/unblock_all.sh
defense/iptables_rules.sh
defense/show_rules.sh
defense/block_ip.sh
defense/apply_decision.py
defense/nftables_rules.sh，可选
defense/nginx.conf，可选
```

### 3.1 清理旧规则

总控脚本会调用：

```bash
bash defense/unblock_all.sh --project-tag cs3611-ddos
```

要求：

```text
只清理本项目添加的规则
不要清空系统中无关的 iptables/nftables 规则
可以通过 comment/tag 标记项目规则
```

### 3.2 启用基础防御规则

总控脚本会调用：

```bash
bash defense/iptables_rules.sh \
  --target-port 8080 \
  --syn-rate 50 \
  --http-rate 120 \
  --project-tag cs3611-ddos
```

必须实现：

```text
1. SYN 单源限速，例如每秒 50 个 SYN 包
2. HTTP 单源限速，例如每秒 120 个请求或连接
3. 对异常 TCP flags 或非法端口流量进行过滤
```

如果使用 `nftables`，也要保持上面的入口脚本存在，可以由 `iptables_rules.sh` 内部转调 `nftables_rules.sh`。

### 3.3 查看规则

总控脚本会调用：

```bash
bash defense/show_rules.sh --project-tag cs3611-ddos
```

输出内容至少包括：

```text
当前黑名单 IP
当前限速规则
当前清洗规则
```

### 3.4 封禁单个 IP

`apply_decision.py` 会调用：

```bash
bash defense/block_ip.sh \
  --ip 10.0.0.1 \
  --reason model_detected_syn_flood \
  --ttl 300 \
  --project-tag cs3611-ddos
```

要求：

```text
--ip           要封禁的源 IP
--reason       封禁原因，写入日志
--ttl          建议封禁时间，单位秒；如果来不及做自动解封，可以先记录但不实现
--project-tag  本项目规则标记
```

不能封禁：

```text
127.0.0.1，当 victim 和 attacker 都在本机时可只做限速不 drop
victim IP
gateway IP
```

如果本地演示必须使用 `127.0.0.1`，`block_ip.sh` 可以改为添加限速规则，而不是直接 DROP。

### 3.5 根据模型判断应用防御

总控脚本会调用：

```bash
python3 defense/apply_decision.py \
  --decision data/logs/demo/decision.json \
  --threshold 0.80 \
  --block-script defense/block_ip.sh \
  --project-tag cs3611-ddos
```

它读取模型组输出的 JSON，发现 `label=attack` 且 `confidence >= threshold` 时，调用 `block_ip.sh`。

输入 JSON 格式见模型组要求。

防御组验收标准：

```text
1. unblock_all.sh 可重复运行，不报错，不误删无关规则
2. iptables_rules.sh 可重复运行，不产生大量重复规则
3. block_ip.sh 能封禁或限速指定源 IP
4. apply_decision.py 能从模型 JSON 中自动执行防御动作
5. show_rules.sh 能让演示时清楚看到规则变化
```

## 4. 模型组必须实现的命令

模型组负责目录：

```text
features/
models/
```

必须交付文件：

```text
features/extract_features.py
features/feature_schema.md
models/train_mlp.py
models/infer.py
models/saved/model.pth 或 models/saved/model.pkl
```

### 4.1 从 PCAP 提取特征

总控脚本会调用：

```bash
python3 features/extract_features.py \
  --input data/pcap/demo/attack_before_defense.pcap \
  --output data/features/demo/attack_before_defense.csv \
  --label attack \
  --attack-type mixed_attack \
  --target-ip 127.0.0.1 \
  --window-size 1
```

输出 CSV 必须包含这些列：

```csv
timestamp,src_ip,dst_ip,protocol,pps,bps,avg_pkt_size,syn_count,ack_count,syn_ack_ratio,unique_src_ips,ip_entropy,label,attack_type
```

字段含义需要写入：

```text
features/feature_schema.md
```

### 4.2 训练模型

正式演示通常不现场训练，但必须支持训练命令：

```bash
python3 models/train_mlp.py \
  --input data/features/train.csv \
  --output models/saved/model.pth \
  --metrics-out data/logs/demo/train_metrics.json
```

`train_metrics.json` 至少包含：

```json
{
  "accuracy": 0.95,
  "precision": 0.94,
  "recall": 0.96,
  "f1": 0.95
}
```

### 4.3 模型推理

总控脚本会调用：

```bash
python3 models/infer.py \
  --input data/features/demo/attack_before_defense.csv \
  --model models/saved/model.pth \
  --output data/logs/demo/decision.json \
  --threshold 0.80
```

输出 JSON 必须符合：

```json
{
  "generated_at": "2026-05-21T12:00:00+08:00",
  "threshold": 0.8,
  "decisions": [
    {
      "src_ip": "10.0.0.1",
      "label": "attack",
      "attack_type": "mixed_attack",
      "confidence": 0.96,
      "action": "block",
      "reason": "model_detected_mixed_attack"
    }
  ]
}
```

如果没有检测到攻击，输出：

```json
{
  "generated_at": "2026-05-21T12:00:00+08:00",
  "threshold": 0.8,
  "decisions": []
}
```

模型组验收标准：

```text
1. 能从攻击组 PCAP 生成统一 CSV
2. 能训练得到模型文件
3. infer.py 能稳定输出 decision.json
4. 至少在文档中给出准确率、召回率、混淆矩阵
5. 输出中的 src_ip 能被防御组脚本直接使用
```

## 5. 各组最终提交检查

整合前，每组先运行自己的接口检查：

```bash
bash scripts/check_group_contract.sh attack
bash scripts/check_group_contract.sh defense
bash scripts/check_group_contract.sh model
```

所有组交付后，整合负责人运行：

```bash
bash scripts/run_demo.sh --check-only
bash scripts/run_demo.sh --dry-run
```

如果检查通过，再运行正式 demo：

```bash
bash scripts/run_demo.sh
```

正式 demo 后，输出材料会在：

```text
data/pcap/<run_id>/
data/features/<run_id>/
data/logs/<run_id>/
```

这些文件直接用于报告和海报：

```text
normal_*.pcap
attack_before_defense_*.pcap
attack_after_defense_*.pcap
normal_*.csv
attack_before_defense_*.csv
attack_after_defense_*.csv
decision_*.json
```
