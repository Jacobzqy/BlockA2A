from typing import List, Optional
import time
from src.blocka2a.clients.errors import InvalidParameterError, ContractError
from src.blocka2a.types import BLSSignature
from src.blocka2a.clients.base_client import BaseClient
from src.blocka2a.contracts import data_anchoring_contract
from src.blocka2a.utils import bn256

class SignatureAggregator(BaseClient):
    # BLS12-381 模数
    BLS12_381_P = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

    def __init__(
        self,
        rpc_endpoint: str,
        data_anchoring_address: str,
        private_key: Optional[str] = None,
        ipfs_gateway: Optional[str] = None,
        default_gas: int = 2_000_000
    ) -> None:
        super().__init__(
            rpc_endpoint=rpc_endpoint,
            private_key=private_key,
            ipfs_gateway=ipfs_gateway,
            default_gas=default_gas,
        )
        self._dac = self._load_contract(data_anchoring_contract.get_contract, data_anchoring_address)

    @staticmethod
    def aggregate(sigs: List[BLSSignature]) -> BLSSignature:
        if not sigs:
            raise InvalidParameterError("No signatures provided for aggregation")
        try:
            start = time.time()      # EVALUATION: Multi-signature generation

            g1_signatures = []
            for sig_bytes in sigs:
                if len(sig_bytes) != 64:
                    raise InvalidParameterError(f"无效的 G1 签名长度：应为 64，实际为 {len(sig_bytes)}")

                x = int.from_bytes(sig_bytes[:32], "big")
                y = int.from_bytes(sig_bytes[32:], "big")
                point = (bn256.FQ(x), bn256.FQ(y))
                g1_signatures.append(bn256.Signature(point))

            agg_sig_point: bn256.Signature = bn256.aggregate_sigs(g1_signatures)

            
            x_bytes = agg_sig_point[0].n.to_bytes(32, "big")
            y_bytes = agg_sig_point[1].n.to_bytes(32, "big")
            agg_sig_bytes = BLSSignature(x_bytes + y_bytes)
            end = time.time()
            print(f"multi-signature generation {end - start:.6f} s")

        except Exception as e:
            raise InvalidParameterError(f"BN254 签名聚合失败: {e}") from e

        return agg_sig_bytes

    @staticmethod
    def bls_signature_to_uint256x2(sig: BLSSignature) -> List[int]:
        """
        将一个 64 字节的 BN254 G1 签名转换为 Solidity 的 uint256[2] 格式，
        代表 G1 点的坐标。

        Args:
            sig: BLSSignature 字节流 (64 字节)。

        Returns:
            一个列表 [x, y]，其中每个元素都是一个 uint256。

        Raises:
            InvalidParameterError: 如果签名格式解码失败或长度不正确。
        """
        if len(sig) != 64:
            raise InvalidParameterError(f"无效的 G1 签名长度，应为 64 字节，实际为 {len(sig)}")

        try:
            # 未压缩的 G1 点是 (x, y)
            x = int.from_bytes(sig[:32], "big")
            y = int.from_bytes(sig[32:], "big")
        except Exception as e:
            raise InvalidParameterError(f"无效的 G1 签名格式: {e}") from e

        return [x, y]

    def submit_task_validation(
        self,
        agg_sig,
        data_hash: bytes,
        milestone: str,
        dids: List[str],
        pks_mask: int
    ) -> bytes:
        """
        在本地验证 BLS 聚合签名，然后将其 uint256[2] 表示提交到
        DataAnchoringContract 进行更新。

        Args:
            agg_sig: `aggregate()` 方法返回的 BLSSignature (64 字节)。
            data_hash: 任务元数据的 32 字节 SHA-256 哈希。
            milestone: 里程碑标识符，例如 "milestone-X"。
            dids: 参与签名的密钥所属的 DID 列表。

        Returns:
            交易哈希 (HexBytes)。

        Raises:
            InvalidParameterError: 如果输入格式错误。
            ContractError: 如果链上更新调用失败。
        """
        start = time.time()
        # if not agg_sig or not isinstance(agg_sig, (bytes, bytearray)):
        #    raise InvalidParameterError("aggregate_signature must be BLSSignature")
        if not agg_sig:
            raise InvalidParameterError("aggregate_signature must be a non-empty BLSSignature")
#        print(f"DEBUG: agg_sig length: {len(agg_sig)}, value: {agg_sig.hex()}")

        # 将 G1 签名转换为 uint256[2] G1 坐标
#        agg_sig_point = self.bls_signature_to_uint256x2(agg_sig)
        agg_sig_point = agg_sig

        # Submit on-chain: update(uint256[4], bytes32, string, string[])
        try:
            tx_hash = self._send_tx(
                self._dac.functions.update,
                agg_sig_point,
                data_hash,
                milestone,
                dids,
                pks_mask
            )
        except Exception as e:
            raise ContractError(f"DAC.update call failed: {e}") from e
        end = time.time()
        print(f"task validation submission {(end - start):.6f} s")

        return tx_hash