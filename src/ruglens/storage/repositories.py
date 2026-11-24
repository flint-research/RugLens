"""Assessment report persistence."""

from __future__ import annotations

from collections.abc import Sequence

from eth_utils.address import is_address, to_checksum_address
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from ruglens.core.exceptions import RepositoryError
from ruglens.core.models import AssessmentReport
from ruglens.storage.database import AssessmentRow, Database


def _storage_address(address: str) -> str:
    """Normalize EVM checksums but preserve Solana Base58 addresses."""
    if is_address(address):
        return to_checksum_address(address)
    return address.strip()


class SQLAlchemyReportRepository:
    """Store and retrieve immutable assessment reports."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def initialize(self) -> None:
        """Ensure the schema exists."""
        await self._database.initialize()

    async def save(self, report: AssessmentReport) -> None:
        """Persist a report; saving the same assessment id is idempotent."""
        try:
            async with self._database.session() as session:
                existing = (
                    await session.execute(
                        select(AssessmentRow).where(
                            AssessmentRow.assessment_id == str(report.assessment_id)
                        )
                    )
                ).scalar_one_or_none()
                if existing is not None:
                    return
                session.add(
                    AssessmentRow(
                        assessment_id=str(report.assessment_id),
                        chain_id=report.chain_id,
                        token_address=_storage_address(report.token_address),
                        block_number=report.block_number,
                        risk_level=report.risk_level.value,
                        data_coverage=report.data_coverage,
                        engine_version=report.engine_version,
                        timestamp=report.timestamp,
                        report_json=report.to_json(indent=None),
                    )
                )
        except (SQLAlchemyError, ValueError) as exc:
            raise RepositoryError(f"Could not persist assessment: {exc}") from exc

    async def get(self, assessment_id: str) -> AssessmentReport | None:
        """Fetch a report by assessment id."""
        try:
            async with self._database.session() as session:
                row = (
                    await session.execute(
                        select(AssessmentRow).where(AssessmentRow.assessment_id == assessment_id)
                    )
                ).scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise RepositoryError(f"Could not read assessment: {exc}") from exc
        if row is None:
            return None
        try:
            return AssessmentReport.from_json(row.report_json)
        except ValueError as exc:
            raise RepositoryError(f"Stored assessment is corrupt: {exc}") from exc

    async def find_latest(
        self,
        chain_id: int,
        token_address: str,
        block_number: int | None = None,
    ) -> AssessmentReport | None:
        """Find the newest report for a token, optionally at an exact block."""
        try:
            checksum = _storage_address(token_address)
            async with self._database.session() as session:
                statement = select(AssessmentRow).where(
                    AssessmentRow.chain_id == chain_id,
                    AssessmentRow.token_address == checksum,
                )
                if block_number is not None:
                    statement = statement.where(AssessmentRow.block_number == block_number)
                statement = statement.order_by(
                    AssessmentRow.timestamp.desc(),
                    AssessmentRow.sequence.desc(),
                ).limit(1)
                row = (await session.execute(statement)).scalar_one_or_none()
        except (SQLAlchemyError, ValueError) as exc:
            raise RepositoryError(f"Could not query assessments: {exc}") from exc
        if row is None:
            return None
        try:
            return AssessmentReport.from_json(row.report_json)
        except ValueError as exc:
            raise RepositoryError(f"Stored assessment is corrupt: {exc}") from exc

    async def list_recent(self, limit: int = 20) -> Sequence[AssessmentReport]:
        """Return the most recent reports (newest first)."""
        if limit <= 0:
            return []
        try:
            async with self._database.session() as session:
                statement = (
                    select(AssessmentRow)
                    .order_by(
                        AssessmentRow.timestamp.desc(),
                        AssessmentRow.sequence.desc(),
                    )
                    .limit(min(limit, 200))
                )
                rows = (await session.execute(statement)).scalars().all()
        except SQLAlchemyError as exc:
            raise RepositoryError(f"Could not list assessments: {exc}") from exc
        reports: list[AssessmentReport] = []
        for row in rows:
            try:
                reports.append(AssessmentReport.from_json(row.report_json))
            except ValueError:
                continue
        return reports

    async def close(self) -> None:
        """Dispose the database engine."""
        await self._database.close()
