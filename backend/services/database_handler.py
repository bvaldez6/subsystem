from typing import Any, Dict, List, Optional
import threading
from neo4j import AsyncGraphDatabase, AsyncDriver, READ_ACCESS, WRITE_ACCESS
import os
import asyncio

class DatabaseHandler:
  """
  Singleton async Neo4j database handler.

  Usage:
    handler = DatabaseHandler.get_instance(
      uri="bolt://localhost:7687",
      user="neo4j",
      password="secret"
    )
    rows = await handler.run_query("MATCH (n) RETURN n LIMIT $limit", {"limit": 10})
  """

  _instance: Optional["DatabaseHandler"] = None
  _lock = threading.Lock()

  def __init__(self, uri: str, user: str, password: str, encrypted: bool = False):
    if DatabaseHandler._instance is not None:
      raise RuntimeError("DatabaseHandler is a singleton. Use get_instance().")
    self._uri = uri
    self._user = user
    self._password = password
    self._encrypted = encrypted
    self._driver: Optional[AsyncDriver] = AsyncGraphDatabase.driver(
      uri, auth=(user, password), encrypted=encrypted
    )

  @classmethod
  def get_instance(
    cls,
    uri: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
    encrypted: bool = False,
  ) -> "DatabaseHandler":
    """
    Return the singleton instance. If not created yet, will create it using
    either provided params or environment variables: NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD.
    """
    with cls._lock:
      if cls._instance is None:
        uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = user or os.getenv("NEO4J_USER", "neo4j")
        password = password or os.getenv("NEO4J_PASSWORD", "neo4j")
        cls._instance = DatabaseHandler(uri, user, password, encrypted)
      return cls._instance

  async def close(self) -> None:
    """Close the underlying driver and clear the singleton instance."""
    if self._driver is not None:
      await self._driver.close()
      self._driver = None
    with DatabaseHandler._lock:
      DatabaseHandler._instance = None

  async def run_query(
    self,
    cypher: str,
    parameters: Optional[Dict[str, Any]] = None,
    write: bool = False,
    single: bool = False,
  ) -> Any:
    """
    Run a cypher query and return results as list[dict] (or a single dict if single=True).

    - cypher: the Cypher query string
    - parameters: dict of parameters for the query
    - write: if True, runs as a write transaction; otherwise as a read transaction
    - single: if True, returns the first record or None

    Example:
      rows = await handler.run_query("MATCH (u:User {id:$id}) RETURN u", {"id": 123})
    """
    if self._driver is None:
      raise RuntimeError("Neo4j driver not initialized")

    access_mode = WRITE_ACCESS if write else READ_ACCESS

    async def _work(tx, cypher_query, params):
      result = await tx.run(cypher_query, **(params or {}))
      records = []
      async for record in result:
        # record.data() returns a dict of the record's keys to Python-native values
        records.append(record.data())
      return records

    session = self._driver.session(default_access_mode=access_mode)
    try:
      if write:
        records = await session.execute_write(_work, cypher, parameters)
      else:
        records = await session.execute_read(_work, cypher, parameters)
    finally:
      await session.close()

    if single:
      return records[0] if records else None
    return records

  # Convenience wrappers
  async def run_read(self, cypher: str, parameters: Optional[Dict[str, Any]] = None, single: bool = False):
    return await self.run_query(cypher, parameters=parameters, write=False, single=single)

  async def run_write(self, cypher: str, parameters: Optional[Dict[str, Any]] = None, single: bool = False):
    return await self.run_query(cypher, parameters=parameters, write=True, single=single)