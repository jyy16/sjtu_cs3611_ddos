# Redis Storage

The demo still writes the CSV, JSON, PCAP, and log files required by the group
contract. When `STORAGE_BACKEND=redis` is enabled, the same structured data is
also written to Redis so the project satisfies the database/storage requirement.

## Enable

Install the Python dependency:

```bash
pip install -r models/requirements.txt
```

Start Redis, for example:

```bash
docker run --rm -p 6379:6379 redis:7
```

Then update `scripts/demo.env`:

```bash
STORAGE_BACKEND=redis
REDIS_URL=redis://127.0.0.1:6379/0
STORAGE_KEY_PREFIX=cs3611:ddos
STORAGE_FAIL_OPEN=0
LIVE_CAPTURE=1
LIVE_DASHBOARD=1
```

Run the preflight:

```bash
bash scripts/run_demo.sh --check-only
```

## Stored Data

For a run id such as `20260605_120000`, Redis keys use this layout:

```text
cs3611:ddos:runs
cs3611:ddos:run:<run_id>
cs3611:ddos:run:<run_id>:artifacts
cs3611:ddos:run:<run_id>:features:<artifact>
cs3611:ddos:run:<run_id>:decision:<artifact>
cs3611:ddos:run:<run_id>:decision:<artifact>:items
cs3611:ddos:run:<run_id>:defense_actions
cs3611:ddos:run:<run_id>:summary
cs3611:ddos:run:<run_id>:events
cs3611:ddos:run:<run_id>:live_features
```

Feature rows and individual decisions are Redis Streams. Summary metadata is
stored in Redis hashes. The final demo summary stores the run status, target,
decision count, and output paths for the PCAP, CSV, and decision JSON artifacts.
During a live demo, `events` stores phase transitions and `live_features` stores
per-window feature rows as soon as tcpdump sees packets.

## Inspect

```bash
redis-cli SMEMBERS cs3611:ddos:runs
redis-cli HGETALL cs3611:ddos:run:<run_id>
redis-cli HGETALL cs3611:ddos:run:<run_id>:summary
redis-cli XRANGE cs3611:ddos:run:<run_id>:events - + COUNT 20
redis-cli XRANGE cs3611:ddos:run:<run_id>:live_features - + COUNT 20
redis-cli XRANGE cs3611:ddos:run:<run_id>:features:attack_before_defense_<run_id> - + COUNT 3
redis-cli XRANGE cs3611:ddos:run:<run_id>:defense_actions - + COUNT 10
```

When `LIVE_DASHBOARD=1`, `run_demo.sh` also starts a local page:

```text
http://127.0.0.1:8090/?run_id=<run_id>
```

Keep `STORAGE_FAIL_OPEN=0` for final grading so Redis problems fail fast during
preflight instead of silently skipping persistence.
