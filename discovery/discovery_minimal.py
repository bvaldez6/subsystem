#!/usr/bin/env python3
"""
discovery/discovery_minimal.py

Minimal discovery worker:
 - Lists local Docker containers
 - Dry-run prints discovered payloads without writing to Neo4j
 - Otherwise upserts Container nodes into Neo4j

Env vars:
 - DOCKER_HOST (default: unix://var/run/docker.sock)
 - NEO4J_URI (default: bolt://localhost:7687)
 - NEO4J_USER (default: neo4j)
 - NEO4J_PASS (default: pass)
 - DISCOVERY_LOG_LEVEL (INFO/DEBUG)
"""
import os
import sys
import json
import time
import logging
from argparse import ArgumentParser
from docker import DockerClient, errors as docker_errors
from neo4j import GraphDatabase, exceptions as neo4j_exceptions

logging.basicConfig(level=os.getenv("DISCOVERY_LOG_LEVEL", "INFO"))
log = logging.getLogger("discovery_worker")

DOCKER_BASE = os.getenv("DOCKER_HOST", "unix://var/run/docker.sock")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "pass")
RETRY_DELAY = int(os.getenv("DISCOVERY_RETRY_DELAY", "5"))

def make_docker_client():
    try:
        return DockerClient(base_url=DOCKER_BASE)
    except Exception as e:
        log.exception("Failed to create Docker client: %s", e)
        raise

def make_neo4j_driver():
    try:
        return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    except Exception as e:
        log.exception("Failed to create Neo4j driver: %s", e)
        raise

def normalize_ports(ports):
    try:
        return json.dumps(ports or {})
    except Exception:
        return json.dumps({})

def upsert_container(tx, cid, name, image, ip, ports_json, host, last_seen, source):
    tx.run(
        """
        MERGE (c:Container {container_id: $cid})
        SET c.name = $name,
            c.image = $image,
            c.ip = $ip,
            c.ports = $ports,
            c.host = $host,
            c.last_seen = $last_seen,
            c.discovery_source = $source
        """,
        cid=cid, name=name, image=image, ip=ip, ports=ports_json, host=host, last_seen=last_seen, source=source
    )

def discover_local(docker_client, driver, dry_run=False, source="local"):
    host = os.uname().nodename if hasattr(os, "uname") else os.getenv("HOSTNAME", "unknown")
    last_seen = int(time.time() * 1000)
    log.info("Starting discovery on host=%s (dry_run=%s)", host, dry_run)
    try:
        containers = docker_client.containers.list(all=True)
    except docker_errors.DockerException:
        log.exception("Docker API error when listing containers")
        raise

    for c in containers:
        try:
            cid = c.id
            name = getattr(c, "name", None) or (c.attrs.get("Name") if c.attrs else None) or cid[:12]
            image = None
            try:
                image = (c.image.tags[0] if getattr(c, "image", None) and c.image.tags else getattr(c, "image", None).short_id)
            except Exception:
                image = c.attrs.get("Config", {}).get("Image") if c.attrs else None

            nets = (c.attrs or {}).get("NetworkSettings", {}).get("Networks", {}) or {}
            ip = None
            if nets:
                ip = next(iter(nets.values())).get("IPAddress")
            ports = (c.attrs or {}).get("NetworkSettings", {}).get("Ports")
            ports_json = normalize_ports(ports)

            payload = {
                "container_id": cid,
                "name": name,
                "image": image,
                "ip": ip,
                "ports": json.loads(ports_json),
                "host": host,
                "last_seen": last_seen,
                "discovery_source": source
            }
            log.info("Discovered container: %s", json.dumps(payload))

            if dry_run:
                continue

            with driver.session() as session:
                session.write_transaction(upsert_container,
                                          cid, name, image, ip, ports_json, host, last_seen, source)

        except Exception:
            log.exception("Failed while processing container %s", getattr(c, "id", "unknown"))

def main():
    parser = ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", dest="dry_run", help="Do not write to Neo4j")
    parser.add_argument("--source", default="local", help="Discovery source label (local/ssh/seed)")
    args = parser.parse_args()

    for _ in range(3):
        try:
            docker_client = make_docker_client()
            break
        except Exception:
            time.sleep(RETRY_DELAY)
    else:
        log.error("Unable to initialize Docker client after retries")
        sys.exit(2)

    for _ in range(3):
        try:
            driver = make_neo4j_driver()
            break
        except Exception:
            time.sleep(RETRY_DELAY)
    else:
        log.error("Unable to initialize Neo4j driver after retries")
        sys.exit(3)

    try:
        discover_local(docker_client, driver, dry_run=args.dry_run, source=args.source)
        log.info("Discovery finished")
    finally:
        try:
            driver.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
