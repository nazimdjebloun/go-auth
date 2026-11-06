"""Run static redisstore tests in isolated Docker Cluster/Sentinel networks.

Build .test-results/redis/redisstore.test with CGO_ENABLED=0 go test -c first.
On Windows build through WSL; this runner can use Docker Desktop's Windows CLI.
Only the containers/network created by this invocation are removed.
"""
import json
from pathlib import Path
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "redis:8@sha256:f245f4c83b84a9e9a0588da1c9456e579455310f0945d5db52cd2ba27f2000cc"
PREFIX = "goauth-redis-" + uuid.uuid4().hex[:10]
CONTAINERS = []


def docker(*args, capture=False):
    result = subprocess.run(["docker", *args], check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def start(name, *command):
    full = PREFIX + "-" + name
    docker("run", "-d", "--name", full, "--network", PREFIX, IMAGE, *command)
    CONTAINERS.append(full)
    return full


def run_tests(name, env):
    args = ["run", "--rm", "--network", PREFIX,
            "--mount", f"type=bind,src={ROOT / '.test-results' / 'redis'},dst=/tests,readonly"]
    for key, value in env.items():
        args.extend(["-e", key + "=" + value])
    docker(*args, IMAGE, "/tests/redisstore.test", "-test.v", "-test.timeout=2m", "-test.run=" + name)


def main():
    if not (ROOT / ".test-results/redis/redisstore.test").is_file():
        raise SystemExit("Build the static Linux redisstore.test binary first")
    docker("network", "create", PREFIX)
    try:
        nodes = [start("cluster" + str(i), "redis-server", "--cluster-enabled", "yes",
                       "--cluster-node-timeout", "3000", "--appendonly", "no") for i in range(3)]
        ips = []
        for node in nodes:
            data = json.loads(docker("inspect", node, capture=True))[0]
            ips.append(data["NetworkSettings"]["Networks"][PREFIX]["IPAddress"] + ":6379")
        docker("exec", nodes[0], "redis-cli", "--cluster", "create", *ips,
               "--cluster-replicas", "0", "--cluster-yes")
        deadline = time.monotonic() + 30
        while True:
            ready = all("cluster_state:ok" in docker("exec", node, "redis-cli", "cluster", "info", capture=True) for node in nodes)
            if ready:
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Redis cluster did not become ready")
            time.sleep(0.2)
        run_tests("^TestRedisCluster$", {"GOAUTH_REDIS_CLUSTER_ADDRS": nodes[0] + ":6379"})
        master = start("master", "redis-server", "--appendonly", "no")
        replica = start("replica", "redis-server", "--replicaof", master, "6379")
        config = ("port 26379\nsentinel resolve-hostnames yes\n"
                  f"sentinel monitor goauth {master} 6379 1\n"
                  "sentinel down-after-milliseconds goauth 500\n"
                  "sentinel failover-timeout goauth 5000\n")
        sentinel = start("sentinel", "sh", "-c",
                         "printf '%s' '" + config + "' > /tmp/sentinel.conf; "
                         "exec redis-server /tmp/sentinel.conf --sentinel")
        run_tests("^TestRedisSentinelFailover$", {"GOAUTH_REDIS_SENTINEL_ADDR": sentinel + ":26379",
                  "GOAUTH_REDIS_REPLICA_ADDR": replica + ":6379"})
        oom = start("oom", "redis-server", "--maxmemory", "512kb", "--maxmemory-policy", "noeviction")
        run_tests("^TestRedisOOMFailsClosed$", {"GOAUTH_REDIS_OOM_ADDR": oom + ":6379"})
    finally:
        for container in reversed(CONTAINERS):
            subprocess.run(["docker", "rm", "-f", container], check=False,
                           stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", PREFIX], check=False,
                       stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
