import os
import sys

from cassandra.cluster import (
    Cluster,
    PlainTextAuthProvider
)

class DatabaseSession (object):
    def __init__(self, username, password, host, port) -> None:
        self.username = username
        self.password = password
        self.host = host
        self.port = port

    def session(self):
        """ Returns the database session """
        cluster = Cluster(
            [self.host],
            port=self.port,
            auth_provider=self._auth_provider()
        )
        session = cluster.connect()

        return session
   
    def _auth_provider(self) -> PlainTextAuthProvider:
        return PlainTextAuthProvider(
            self.username, \
            self.password
        )
