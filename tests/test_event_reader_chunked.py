from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import config  # noqa: E402
import event_reader  # noqa: E402


class _FakeWinError(Exception):
    def __init__(self, winerror: int, op: str, message: str) -> None:
        super().__init__(winerror, op, message)
        self.winerror = winerror


def _make_sample_xml(record_id: int, channel: str = config.SYSMON_CHANNEL) -> str:
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "<System>"
        "<Provider Name='Microsoft-Windows-Sysmon'/>"
        "<EventID>1</EventID>"
        f"<EventRecordID>{record_id}</EventRecordID>"
        "<TimeCreated SystemTime='2026-11-28T01:00:00.0000000Z'/>"
        f"<Channel>{channel}</Channel>"
        "</System>"
        "<EventData>"
        "<Data Name='UtcTime'>2026-11-28 01:00:00.000</Data>"
        f"<Data Name='ProcessId'>{1000 + record_id}</Data>"
        "<Data Name='Image'>C:\\Windows\\System32\\notepad.exe</Data>"
        "<Data Name='CommandLine'>notepad.exe</Data>"
        "<Data Name='ParentProcessId'>500</Data>"
        "<Data Name='ParentCommandLine'>C:\\Windows\\explorer.exe</Data>"
        "</EventData>"
        "</Event>"
    )


class _FakeEvtLog:
    def __init__(self, total_records: int, fail_1734_above: int | None = None, end_error: Exception | None = None) -> None:
        self.EvtQueryChannelPath = 1
        self.EvtQueryForwardDirection = 2
        self.EvtQueryReverseDirection = 4
        self.EvtRenderEventXml = 1
        self._records = [100 + i for i in range(total_records)]
        self._cursor = 0
        self._fail_1734_above = fail_1734_above
        self._end_error = end_error
        self.asked_batches: list[int] = []

    def EvtQuery(self, channel, flags, xpath_query, bookmark):
        return object()

    def EvtNext(self, query_handle, ask, timeout_ms, flags):
        self.asked_batches.append(ask)
        if self._fail_1734_above is not None and ask > self._fail_1734_above:
            raise _FakeWinError(1734, "EvtNext", "The array bounds are invalid.")
        if self._cursor >= len(self._records):
            if self._end_error is not None:
                raise self._end_error
            return []
        end = min(self._cursor + ask, len(self._records))
        chunk = [f"HANDLE:{rid}" for rid in self._records[self._cursor:end]]
        self._cursor = end
        return chunk

    def EvtRender(self, evt_handle, render_flag):
        rid = int(str(evt_handle).split(":", 1)[1])
        return _make_sample_xml(rid)


class TestChunkedEventFetch(unittest.TestCase):
    def test_chunked_fetch_reads_multiple_batches_up_to_max_events(self) -> None:
        fake = _FakeEvtLog(total_records=100)
        with (
            patch.object(event_reader, "HAS_PYWIN32", True),
            patch.object(event_reader, "win32evtlog", fake),
        ):
            xmls = event_reader.fetch_event_xmls_chunked(
                query_handle=object(),
                max_events=74,
                timeout_ms=2000,
                batch_size=32,
                channel=config.SYSMON_CHANNEL,
            )

        self.assertEqual(len(xmls), 74)
        self.assertEqual(fake.asked_batches, [32, 32, 10])

    def test_chunked_fetch_recovers_from_1734_by_halving_batch_size(self) -> None:
        fake = _FakeEvtLog(total_records=20, fail_1734_above=8)
        with (
            patch.object(event_reader, "HAS_PYWIN32", True),
            patch.object(event_reader, "win32evtlog", fake),
        ):
            xmls = event_reader.fetch_event_xmls_chunked(
                query_handle=object(),
                max_events=100,
                timeout_ms=2000,
                batch_size=32,
                channel=config.SYSMON_CHANNEL,
            )

        self.assertEqual(len(xmls), 20)
        self.assertEqual(fake.asked_batches, [32, 16, 8, 8, 8, 8])

    def test_chunked_fetch_handles_eof_error_259_and_preserves_partial_events(self) -> None:
        fake = _FakeEvtLog(
            total_records=10,
            end_error=_FakeWinError(259, "EvtNext", "No more data is available."),
        )
        with tempfile.TemporaryDirectory() as tmp:
            cp_mgr = event_reader.CheckpointManager(Path(tmp) / "checkpoint.json")
            cp_mgr.update(config.SYSMON_CHANNEL, 50, persist=False)
            reader = event_reader.WindowsEventReader(cp_mgr)
            with (
                patch.object(event_reader, "HAS_PYWIN32", True),
                patch.object(event_reader, "win32evtlog", fake),
            ):
                events = reader.read_channel_events(
                    channel=config.SYSMON_CHANNEL,
                    target_event_ids={1},
                    max_events=100,
                )

        self.assertEqual(len(events), 10)
        self.assertEqual([ev.event_record_id for ev in events], list(range(100, 110)))
        self.assertEqual(cp_mgr.get_last_record_id(config.SYSMON_CHANNEL), 109)


if __name__ == "__main__":
    unittest.main(verbosity=2)
