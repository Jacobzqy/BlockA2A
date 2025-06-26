"""Provides a simplified client for interacting with an IPFS node.

This module offers a high-level wrapper around the ipfshttpclient library,
streamlining common operations such as adding and retrieving data. It aims to
abstract away inconsistencies between different versions of the underlying
library, providing a stable and straightforward interface.

Key Features:
  - Adding and retrieving raw bytes, JSON objects, and local files.
  - Simplified connection management to an IPFS daemon.
  - Consistent error handling for IPFS operations.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

import ipfshttpclient
from ipfshttpclient.exceptions import Error as IPFSError


class IPFSClient:
    """Manages a connection to an IPFS daemon for simplified operations.

    This class wraps the `ipfshttpclient` to offer a more consistent and
    high-level API for common tasks like adding and retrieving data via the
    IPFS HTTP API.
    """

    def __init__(self, gateway: str) -> None:
        """Initializes the IPFSClient and connects to the specified daemon.

        Args:
            gateway: The multiaddress or URL of the IPFS HTTP API endpoint
                (e.g., '/dns/localhost/tcp/5001/http').
        """
        self._gateway = gateway
        self._client = ipfshttpclient.connect(self._gateway)

    def add_bytes(self, data: bytes) -> str:
        """Uploads a bytes object to IPFS.

        Args:
            data: The raw bytes to be added to IPFS.

        Returns:
            The IPFS Content Identifier (CID) for the added data.

        Raises:
            IPFSError: If the upload operation fails.
        """
        return self._client.add_bytes(data)

    def add_json(self, obj: Any) -> str:
        """Serializes a Python object to JSON and adds it to IPFS.

        This method attempts to use the native add_json function if the
        client library supports it. Otherwise, it falls back to serializing
        the object into a compact UTF-8 encoded JSON string and uploading
        it as raw bytes.

        Args:
            obj: A JSON-serializable Python object.

        Returns:
            The IPFS CID for the added JSON content.

        Raises:
            IPFSError: If the upload operation fails.
        """
        try:
            return self._client.add_json(obj)
        except AttributeError:
            # Fallback for older library versions
            payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            return self._client.add_bytes(payload)

    def add_file(self, path: Union[str, Path]) -> str:
        """Uploads a local file to IPFS.

        This function handles different response structures from various
        `ipfshttpclient` versions to reliably extract the CID.

        Args:
            path: The local filesystem path to the file.

        Returns:
            The IPFS CID for the added file.

        Raises:
            RuntimeError: If the CID cannot be parsed from the IPFS daemon's
                response.
            IPFSError: If the upload operation fails.
        """
        result = self._client.add_file(str(path))
        # Accommodate both list (v0.4.x) and dict (v0.8.x) responses.
        if isinstance(result, list):
            entry = result[-1]
        else:
            entry = result

        cid = entry.get("Hash") or entry.get("hash")
        if not cid:
            raise RuntimeError(f"Unexpected IPFS add result: {result}")
        return cid

    def get(self, cid: str) -> bytes:
        """Retrieves raw content from IPFS by its CID.

        Args:
            cid: The IPFS CID of the content to retrieve.

        Returns:
            The raw bytes of the content.

        Raises:
            IPFSError: If the retrieval operation fails.
        """
        return self._client.cat(cid)

    def get_json(self, cid: str) -> Any:
        """Retrieves and deserializes a JSON object from IPFS.

        Args:
            cid: The IPFS CID of the JSON content.

        Returns:
            The deserialized Python object.

        Raises:
            IPFSError: If the retrieval operation fails.
            json.JSONDecodeError: If the retrieved content is not valid JSON.
        """
        raw = self.get(cid)
        return json.loads(raw.decode("utf-8"))

    def close(self) -> None:
        """Closes the connection to the IPFS daemon.

        Attempts to gracefully close the client connection and suppresses any
        `IPFSError` that might occur during the process.
        """
        try:
            self._client.close()
        except IPFSError:
            # Suppress errors on close, as the primary goal is cleanup.
            pass