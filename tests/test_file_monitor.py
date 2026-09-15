from pathlib import Path

from watchfiles import Change

from privashield_file_monitor.monitor import file_entropy, sample_file, summarize_changes


def test_entropy_and_sampling(tmp_path: Path) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(bytes(range(256)) * 256)
    sample = sample_file(target)
    assert sample is not None
    assert sample.size_bytes == 65536
    assert sample.entropy > 7.9
    assert len(sample.path_hash) == 64


def test_empty_file_entropy_is_zero(tmp_path: Path) -> None:
    target = tmp_path / "empty.txt"
    target.write_bytes(b"")
    assert file_entropy(target) == 0.0


def test_change_summary_estimates_extension_renames() -> None:
    changes = {
        (Change.deleted, "/watch/report.docx"),
        (Change.added, "/watch/report.locked"),
        (Change.modified, "/watch/other.txt"),
    }
    summary = summarize_changes(changes)
    assert summary["file_operations"] == 3
    assert summary["renamed_files"] == 1
    assert summary["extension_changes"] == 1
