from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .policy_models import (
    PolicyCapabilities,
    PolicyHistoryEvent,
    PolicyHistoryEventType,
    PolicyRevision,
    PolicyStatus,
    SignedPolicyEnvelope,
)
from .policy_repository import PolicyRepository
from .policy_signing import policy_content_digest, verify_policy


class PolicyError(Exception):
    pass


class PolicyConfigurationError(PolicyError):
    pass


class PolicyNotFoundError(PolicyError):
    pass


class PolicyConflictError(PolicyError):
    pass


class PolicySignatureError(PolicyError):
    pass


class PolicyService:
    def __init__(
        self,
        repository: PolicyRepository,
        *,
        verification_key: Ed25519PublicKey | None,
        key_id: str,
    ) -> None:
        self._repository = repository
        self._verification_key = verification_key
        self._key_id = key_id

    def capabilities(self) -> PolicyCapabilities:
        return PolicyCapabilities(
            verification_configured=self._verification_key is not None,
            configured_key_id=self._key_id,
        )

    def _require_verification_key(self) -> Ed25519PublicKey:
        if self._verification_key is None:
            raise PolicyConfigurationError(
                "policy verification is not configured; set "
                "PRIVASHIELD_POLICY_VERIFICATION_PUBLIC_KEY"
            )
        return self._verification_key

    def _verify_envelope(self, envelope: SignedPolicyEnvelope) -> None:
        verification_key = self._require_verification_key()
        if envelope.key_id != self._key_id:
            raise PolicySignatureError(
                f"policy key_id {envelope.key_id!r} does not match configured key_id"
            )
        if not verify_policy(envelope, verification_key):
            raise PolicySignatureError("policy signature verification failed")

    def _verify_revision(self, revision: PolicyRevision) -> None:
        envelope = SignedPolicyEnvelope(
            policy_id=revision.policy_id,
            version=revision.version,
            document=revision.document,
            key_id=revision.key_id,
            algorithm=revision.algorithm,
            signature=revision.signature,
        )
        self._verify_envelope(envelope)
        digest = policy_content_digest(
            policy_id=revision.policy_id,
            version=revision.version,
            document=revision.document,
            key_id=revision.key_id,
            algorithm=revision.algorithm,
        )
        if digest != revision.content_digest:
            raise PolicySignatureError("policy content digest verification failed")

    async def register(
        self,
        envelope: SignedPolicyEnvelope,
        *,
        created_by: str,
        identity_verified: bool = False,
    ) -> PolicyRevision:
        self._verify_envelope(envelope)
        existing = await self._repository.list_revisions(envelope.policy_id)
        expected_version = existing[0].version + 1 if existing else 1
        if envelope.version != expected_version:
            raise PolicyConflictError(
                f"policy version must be the next monotonic revision ({expected_version})"
            )

        digest = policy_content_digest(
            policy_id=envelope.policy_id,
            version=envelope.version,
            document=envelope.document,
            key_id=envelope.key_id,
            algorithm=envelope.algorithm,
        )
        revision = PolicyRevision(
            policy_id=envelope.policy_id,
            version=envelope.version,
            document=envelope.document,
            key_id=envelope.key_id,
            algorithm=envelope.algorithm,
            signature=envelope.signature,
            content_digest=digest,
            created_by=created_by,
            signature_valid=True,
            enforced=False,
        )
        event = PolicyHistoryEvent(
            policy_id=revision.policy_id,
            version=revision.version,
            event_type=PolicyHistoryEventType.REGISTERED,
            actor=created_by,
            metadata={
                "content_digest": digest,
                "key_id": envelope.key_id,
                "identity_verified": identity_verified,
            },
        )
        try:
            return await self._repository.register_revision(revision, event)
        except ValueError as exc:
            raise PolicyConflictError(str(exc)) from exc

    async def get(self, policy_id: UUID, version: int) -> PolicyRevision:
        revision = await self._repository.get_revision(policy_id, version)
        if revision is None:
            raise PolicyNotFoundError("policy revision does not exist")
        return revision

    async def list_versions(self, policy_id: UUID) -> list[PolicyRevision]:
        return await self._repository.list_revisions(policy_id)

    async def history(self, policy_id: UUID) -> list[PolicyHistoryEvent]:
        return await self._repository.list_history(policy_id)

    async def active(self, policy_id: UUID) -> PolicyRevision | None:
        return await self._repository.active_revision(policy_id)

    async def approve(
        self,
        policy_id: UUID,
        version: int,
        *,
        approved_by: str,
        identity_verified: bool = False,
    ) -> PolicyRevision:
        revision = await self.get(policy_id, version)
        if revision.status is not PolicyStatus.DRAFT:
            raise PolicyConflictError("only draft policy revisions can be approved")
        if approved_by == revision.created_by:
            raise PolicyConflictError("policy approval requires a second operator")
        self._verify_revision(revision)

        now = datetime.now(UTC)
        revision.status = PolicyStatus.APPROVED
        revision.approved_by = approved_by
        revision.approved_at = now
        event = PolicyHistoryEvent(
            policy_id=policy_id,
            version=version,
            event_type=PolicyHistoryEventType.APPROVED,
            actor=approved_by,
            created_at=now,
            metadata={
                "signature_verified": True,
                "identity_verified": identity_verified,
            },
        )
        try:
            await self._repository.commit_transition([revision], [event])
        except ValueError as exc:
            raise PolicyConflictError(str(exc)) from exc
        return revision

    async def activate(
        self,
        policy_id: UUID,
        version: int,
        *,
        activated_by: str,
        identity_verified: bool = False,
    ) -> PolicyRevision:
        target = await self.get(policy_id, version)
        if target.status is not PolicyStatus.APPROVED:
            raise PolicyConflictError("policy revision must be approved before activation")
        self._verify_revision(target)

        now = datetime.now(UTC)
        current = await self._repository.active_revision(policy_id)
        revisions: list[PolicyRevision] = []
        events: list[PolicyHistoryEvent] = []
        if current is not None:
            self._verify_revision(current)
            current.status = PolicyStatus.SUPERSEDED
            revisions.append(current)
            events.append(
                PolicyHistoryEvent(
                    policy_id=policy_id,
                    version=current.version,
                    event_type=PolicyHistoryEventType.SUPERSEDED,
                    actor=activated_by,
                    created_at=now,
                    metadata={
                        "superseded_by_version": version,
                        "identity_verified": identity_verified,
                    },
                )
            )

        target.status = PolicyStatus.ACTIVE
        target.activated_by = activated_by
        target.activated_at = now
        revisions.append(target)
        events.append(
            PolicyHistoryEvent(
                policy_id=policy_id,
                version=version,
                event_type=PolicyHistoryEventType.ACTIVATED,
                actor=activated_by,
                created_at=now,
                metadata={
                    "signature_verified": True,
                    "identity_verified": identity_verified,
                    "activation_effect": "simulation-governance-only",
                    "enforced": False,
                },
            )
        )
        try:
            await self._repository.commit_transition(revisions, events)
        except ValueError as exc:
            raise PolicyConflictError(str(exc)) from exc
        return target

    async def rollback(
        self,
        policy_id: UUID,
        target_version: int,
        *,
        actor: str,
        identity_verified: bool = False,
    ) -> PolicyRevision:
        current = await self._repository.active_revision(policy_id)
        if current is None:
            raise PolicyConflictError("policy has no active revision to roll back")
        if target_version >= current.version:
            raise PolicyConflictError("rollback target must be an earlier policy version")

        target = await self.get(policy_id, target_version)
        if target.status not in {PolicyStatus.APPROVED, PolicyStatus.SUPERSEDED}:
            raise PolicyConflictError("rollback target must have prior approval")
        if target.approved_by is None or target.approved_at is None:
            raise PolicyConflictError("rollback target has no approval history")
        self._verify_revision(current)
        self._verify_revision(target)

        now = datetime.now(UTC)
        current.status = PolicyStatus.SUPERSEDED
        target.status = PolicyStatus.ACTIVE
        target.activated_by = actor
        target.activated_at = now
        events = [
            PolicyHistoryEvent(
                policy_id=policy_id,
                version=current.version,
                event_type=PolicyHistoryEventType.SUPERSEDED,
                actor=actor,
                created_at=now,
                metadata={
                    "superseded_by_version": target_version,
                    "rollback": True,
                    "identity_verified": identity_verified,
                },
            ),
            PolicyHistoryEvent(
                policy_id=policy_id,
                version=target_version,
                event_type=PolicyHistoryEventType.ROLLED_BACK,
                actor=actor,
                created_at=now,
                metadata={
                    "from_version": current.version,
                    "signature_verified": True,
                    "identity_verified": identity_verified,
                    "activation_effect": "simulation-governance-only",
                    "enforced": False,
                },
            ),
        ]
        try:
            await self._repository.commit_transition([current, target], events)
        except ValueError as exc:
            raise PolicyConflictError(str(exc)) from exc
        return target
