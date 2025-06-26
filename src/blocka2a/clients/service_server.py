from typing import List, Set

from web3 import Web3

from src.blocka2a.clients import ContractError, BaseClient, IdentityError, InvalidParameterError
from src.blocka2a.contracts import access_control_contract
from src.blocka2a.types import AccessToken, Policy


class ServiceServer(BaseClient):
    def __init__(
        self,
        rpc_endpoint: str,
        acc_address: str,
        private_key: str,
        resource_identifier: str,
        default_gas: int = 2_000_000,
    ):
        super().__init__(
            rpc_endpoint=rpc_endpoint,
            private_key=private_key,
            default_gas=default_gas,
            ipfs_gateway=None
        )
        self._acc = self._load_contract(access_control_contract.get_contract, acc_address)
        self._resource_identifier = resource_identifier
        self._registered_actions: Set[str] = set()

    def register_action(self, action_identifier: str) -> bool:
        if action_identifier in self._registered_actions:
            return False
        self._registered_actions.add(action_identifier)
        return True

    

    @classmethod
    def get_token_hash(cls, token: AccessToken) -> bytes:
        # 使用点语法访问属性
        return Web3.solidity_keccak(
            ['string', 'string', 'string', 'string', 'string', 'string', 'uint256'],
            [
                token.agentDID, "|", 
                token.actionIdentifier, "|", 
                token.resourceIdentifier, "|", 
                token.expiry
            ]
        )

    # def verify_token(self, token: AccessToken) -> bool:
    #     if token['resourceIdentifier'] != self._resource_identifier:
    #         return False

    #     if token['actionIdentifier'] not in self._registered_actions:
    #         return False

    #     token_hash = self.get_token_hash(token)

    #     try:
    #         is_valid = self._acct.functions.verifyTokenHash(token_hash).call()
    #         return is_valid
    #     except Exception as e:
    #         raise ContractError(f"verifyTokenHash contract call failed: {e}") from e

    # 修改 ServiceServer 类中的 verify_token 方法
    def verify_token(self, token: AccessToken) -> bool:
        # 使用点语法访问属性而不是字典语法
        if token.resourceIdentifier != self._resource_identifier:
            return False

        if token.actionIdentifier not in self._registered_actions:
            return False

        token_hash = self.get_token_hash(token)

        try:
            is_valid = self._acc.functions.verifyTokenHash(token_hash).call()
            return is_valid
        except Exception as e:
            raise ContractError(f"verifyTokenHash contract call failed: {e}") from e

    def register_policy(
        self,
        action_identifier: str,
        policy: Policy,
        agg_sig: List[int],
        pks_mask: int
    ) -> bytes:
        if not self._acct:
            raise IdentityError("A private key is required to register a policy.")

        if action_identifier not in self._registered_actions:
            raise InvalidParameterError(f"Action '{action_identifier}' is not registered for this resource.")

        params = {
            "resourceIdentifier": self._resource_identifier,
            "actionIdentifier": action_identifier,
            "policyTypeStr": policy.policy_type,
            "policyParameters": policy.policy_param,
            "aggSig": agg_sig,
            "pksMask": pks_mask
        }

        try:
            tx_hash = self._send_tx(
                self._acc.functions.registerPolicy,
                params
            )
            return tx_hash
        except Exception as e:
            raise ContractError(f"registerPolicy transaction failed: {e}") from e

    def remove_policy(
        self,
        action_identifier: str,
        policy: Policy,
        agg_sig: List[int],
        pks_mask: int
    ) -> bytes:
        if not self._acct:
            raise IdentityError("A private key is required to remove a policy.")

        if action_identifier not in self._registered_actions:
            raise InvalidParameterError(f"Action '{action_identifier}' is not registered for this resource.")

        params = {
            "resourceIdentifier": self._resource_identifier,
            "actionIdentifier": action_identifier,
            "policyTypeStr": policy.policy_type,
            "policyParameters": policy.policy_param,
            "aggSig": agg_sig,
            "pksMask": pks_mask
        }

        try:
            tx_hash = self._send_tx(
                self._acc.functions.removePolicy,
                params
            )
            return tx_hash
        except Exception as e:
            raise ContractError(f"removePolicy transaction failed: {e}") from e

