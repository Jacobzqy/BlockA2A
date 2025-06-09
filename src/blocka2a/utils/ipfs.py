import json
import ipfshttpclient
from ipfshttpclient.exceptions import Error as IPFSError
from typing import Any, Union
from pathlib import Path

class IPFSClient:
    """
    Wrapper around ipfshttpclient.Client for simplified IPFS operations.
    """

    def __init__(self, gateway: str) -> None:
        """
        Initialize an IPFS client.

        Args:
            gateway: Multiaddress or URL of the IPFS HTTP API (e.g. '/dns/localhost/tcp/5001/http').
        """
        self._gateway = gateway
        # Connect to the local or remote IPFS daemon
        self._client = ipfshttpclient.connect(self._gateway)

    def add_bytes(self, data: bytes) -> str:
        """
        Add raw bytes to IPFS.

        Args:
            data: Byte content to add.

        Returns:
            The CID (as a base58 string) of the added content.

        Raises:
            IPFSError: If the IPFS operation fails.
        """
        # ipfshttpclient returns the hash of the data added
        return self._client.add_bytes(data)

    def add_json(self, obj: Any) -> str:
        """
        Add a JSON-serializable Python object to IPFS.

        Tries to use the native `add_json` API if available; otherwise
        falls back to serializing and using `add_bytes`.

        Args:
            obj: A JSON-serializable Python object.

        Returns:
            The CID of the added JSON content.

        Raises:
            IPFSError: If the IPFS operation fails.
        """
        try:
            # Some ipfshttpclient versions provide add_json directly
            return self._client.add_json(obj)
        except AttributeError:
            # Fallback: serialize the object and add as bytes
            payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            return self._client.add_bytes(payload)

    def add_file(self, path: Union[str, Path]) -> str:
        """
        Add a file from the local filesystem to IPFS.

        Args:
            path: Path to the file to be added.

        Returns:
            The CID of the added file.

        Raises:
            RuntimeError: If the IPFS response is in an unexpected format.
            IPFSError: If the IPFS operation fails.
        """
        # ipfshttpclient.Client.add may return a dict or a list of dicts
        result = self._client.add_file(str(path))
        # Handle v0.4.x (list of dicts) and v0.8.x (single dict)
        if isinstance(result, list):
            entry = result[-1]
        else:
            entry = result
        cid = entry.get("Hash") or entry.get("hash")
        if not cid:
            raise RuntimeError(f"Unexpected IPFS add result: {result}")
        return cid

    def get(self, cid: str) -> bytes:
        """
        Retrieve raw bytes from IPFS for a given CID.

        Args:
            cid: The IPFS Content Identifier.

        Returns:
            Raw bytes of the stored content.

        Raises:
            IPFSError: If the IPFS operation fails.
        """
        return self._client.cat(cid)

    def get_json(self, cid: str) -> Any:
        """
        Retrieve and parse a JSON object stored under the given CID.

        Args:
            cid: The IPFS Content Identifier of the JSON content.

        Returns:
            The parsed Python object.

        Raises:
            IPFSError: If the IPFS operation fails.
            json.JSONDecodeError: If the retrieved bytes cannot be decoded as JSON.
        """
        raw = self.get(cid)
        return json.loads(raw.decode("utf-8"))

    def close(self) -> None:
        """
        Close the underlying IPFS client connection.
        """
        try:
            self._client.close()
        except IPFSError:
            pass