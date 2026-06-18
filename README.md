# sjtu_cs3611_ddos

Project 9: DDoS 攻击对抗与基于深度学习的智能防御系统。

完整的项目报告和操作手册请参考`report`文件夹，以下是简略版的操作手册

## 环境准备

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r models/requirements.txt
cp scripts/demo.env.example scripts/demo.env
```

如果使用虚拟环境，确认 `scripts/demo.env` 中有：

```bash
PYTHON=.venv/bin/python
```

如果之前的 victim HTTP 服务没有正常退出，先清掉旧的 8080 服务，避免端口占用：

```bash
pkill -f "python -m http.server 8080" || true
```

## 普通演示

普通演示是前后对比流程：正常流量、攻击前抓包、模型推理封禁、防御后再次攻击。

```bash
bash scripts/run_demo.sh --check-only
bash scripts/run_demo.sh --run-id demo_01
```

生成普通演示可视化：

```bash
.venv/bin/python scripts/visualize_demo.py --run-id demo_01
```

最终结果显示在`data/logs/demo_01/demo_visualization_demo_01.html`

## 实时攻防演示

实时演示用于展示“前台混合攻击运行时，后台同步抓包、推理并自动封禁”。

```bash
bash scripts/run_realtime_demo.sh --check-only
bash scripts/run_realtime_demo.sh --run-id realtime_demo_01
```

如果机器较慢，建议拉长前台攻击时间，确保封禁动作发生在攻击仍在运行时：

```bash
REALTIME_ATTACK_SECONDS=180 bash scripts/run_realtime_demo.sh --run-id realtime_demo_01
```

生成实时攻防可视化：

```bash
.venv/bin/python scripts/visualize_realtime_demo.py --run-id realtime_demo_01
```

最终结果显示在`data\logs\realtime_demo_11\realtime_visualization_realtime_demo_01.html`

## CDN / 边缘代理集成

CDN 集成由 `defense/nginx.conf` 提供：`client -> http://127.0.0.1:8081/ -> origin http://127.0.0.1:8080/`。总控脚本不会自动启动 nginx，需要在运行 demo 前先启动边缘代理。

如果系统没有 nginx，先安装：

```bash
sudo apt-get update
sudo apt-get install -y nginx
```

检查并启动本项目的 nginx edge：

```bash
nginx -t -c "$(pwd)/defense/nginx.conf"
nginx -c "$(pwd)/defense/nginx.conf"
curl -i http://127.0.0.1:8081/healthz
```

让正常流量和 HTTP Flood 经过 CDN edge，SYN/UDP 仍打 origin 的 `127.0.0.1:8080`：

```bash
TARGET_URL=http://127.0.0.1:8081/ bash scripts/run_demo.sh --run-id cdn_demo_01
TARGET_URL=http://127.0.0.1:8081/ bash scripts/run_realtime_demo.sh --run-id cdn_realtime_01
```

如果希望攻击目标端口也切到 edge 的 `8081`，先手动启动 origin，再用 `START_TARGET=0` 运行 demo：

```bash
.venv/bin/python -m http.server 8080 --bind 127.0.0.1 --directory demo_site \
  >/tmp/cs3611-origin.log 2>&1 &

START_TARGET=0 TARGET_IP=127.0.0.1 TARGET_PORT=8081 TARGET_URL=http://127.0.0.1:8081/ \
  bash scripts/run_demo.sh --run-id cdn_edge_port_01
```

查看 CDN edge 响应头和访问日志：

```bash
curl -I http://127.0.0.1:8081/
tail -f /tmp/cs3611-nginx-access.log
```

## Redis 存储

启动 Redis：

```bash
docker run --rm --name cs3611-redis -p 6379:6379 redis:7
```

修改 `scripts/demo.env`：

```bash
STORAGE_BACKEND=redis
REDIS_URL=redis://127.0.0.1:6379/0
STORAGE_KEY_PREFIX=cs3611:ddos
STORAGE_FAIL_OPEN=0
```

查看 Redis 中的 run：

```bash
redis-cli SMEMBERS cs3611:ddos:runs
redis-cli HGETALL cs3611:ddos:run:<run_id>
```

查看特征、模型决策和防御动作：

```bash
redis-cli XRANGE cs3611:ddos:run:<run_id>:features:normal_<run_id> - + COUNT 5
redis-cli XRANGE cs3611:ddos:run:<run_id>:decision:decision_<run_id>:items - + COUNT 10
redis-cli XRANGE cs3611:ddos:run:<run_id>:defense_actions - + COUNT 10
```

查看 `defense/block_ip.sh` 实际执行日志的 Redis 备份：

```bash
redis-cli XRANGE cs3611:ddos:run:<run_id>:defense_block_log - + COUNT 10
```

## 清理

清理本项目创建的防御规则：

```bash
bash defense/unblock_all.sh --project-tag cs3611-ddos
```

停止 Redis：

```bash
docker stop cs3611-redis
```

停止 CDN edge：

```bash
nginx -s stop -c "$(pwd)/defense/nginx.conf" || true
```
