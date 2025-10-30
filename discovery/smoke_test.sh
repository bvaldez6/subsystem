#!/bin/bash
set -e
echo "[+] Running local container discovery..."
python3 discovery_minimal.py
echo "[+] Verifying Neo4j entries..."
cypher-shell -u "${NEO4J_USER:-neo4j}" -p "${NEO4J_PASS:-pass}" "MATCH (c:Container) RETURN c.name, c.image, c.ip LIMIT 5;"
