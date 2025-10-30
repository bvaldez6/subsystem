#!/bin/bash
set -e
echo "[+] Loading Neo4j base schema..."
cypher-shell -u "${NEO4J_USER:-neo4j}" -p "${NEO4J_PASS:-pass}" -f ./cypher/base_schema.cypher
echo "[+] Schema loaded."
