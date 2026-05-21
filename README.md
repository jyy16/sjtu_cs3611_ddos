# sjtu_cs3611_ddos

题目九：DDoS 攻击对抗与基于深度学习的智能防御系统设计。

最终演示入口：

```bash
cp scripts/demo.env.example scripts/demo.env
bash scripts/run_demo.sh --check-only
bash scripts/run_demo.sh
```

三组需要实现的具体命令见：

```text
docs/group_command_requirements.md
```

各组接口自检：

```bash
bash scripts/check_group_contract.sh attack
bash scripts/check_group_contract.sh defense
bash scripts/check_group_contract.sh model
```
