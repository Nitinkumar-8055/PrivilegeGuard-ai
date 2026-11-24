import os
import sys
import time
import threading
import logging
import platform
import subprocess
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from config import Config
from services.windows_parser import WindowsEventParser
from services.ingestion import IngestionService
from services.detection_engine import DetectionEngine
from services.correlation import IncidentCorrelationEngine

logger = logging.getLogger("privilegeguard.collector")

# Optional ctypes Windows Event Log bindings
IS_WINDOWS = platform.system() == "Windows"
wevtapi = None
if IS_WINDOWS:
    try:
        import ctypes
        from ctypes import wintypes
        wevtapi = ctypes.windll.wevtapi
        # Setup function signatures
        wevtapi.EvtQuery.restype = wintypes.HANDLE
        wevtapi.EvtQuery.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]

        wevtapi.EvtNext.restype = wintypes.BOOL
        wevtapi.EvtNext.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD)
        ]

        wevtapi.EvtRender.restype = wintypes.BOOL
        wevtapi.EvtRender.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD)
        ]
        wevtapi.EvtClose.restype = wintypes.BOOL
        wevtapi.EvtClose.argtypes = [wintypes.HANDLE]
    except Exception as e:
        logger.warning(f"Could not initialize wevtapi.dll ctypes bindings: {e}")
        wevtapi = None


class BaseEventSource:
    """Abstract interface for Windows event log sources."""
    def test_access(self, channel: str) -> Tuple[bool, Optional[str]]:
        raise NotImplementedError

    def fetch_events(self, channel: str, last_record_id: int, max_records: int) -> Tuple[List[str], Optional[str]]:
        raise NotImplementedError


class NativeWindowsEventSource(BaseEventSource):
    """
    Genuine Windows Event Log reader using native wevtapi.dll (or wevtutil fallback).
    Requires administrative privileges or membership in 'Event Log Readers' for the Security log.
    """
    def __init__(self):
        self.use_ctypes = wevtapi is not None

    def test_access(self, channel: str = "Security") -> Tuple[bool, Optional[str]]:
        if not IS_WINDOWS:
            return False, "Not running on Windows operating system."

        # Test via native wevtapi if available
        if self.use_ctypes:
            import ctypes
            h_q = wevtapi.EvtQuery(None, channel, "*", 1)  # EvtQueryChannelPath
            if h_q:
                wevtapi.EvtClose(h_q)
                return True, None
            err = ctypes.GetLastError()
            if err == 5:
                return False, "Access is denied (Error 5). Administrator privileges or 'Event Log Readers' group membership required to read the Security channel."
            return False, f"Failed to query {channel} channel (Windows Error {err})."

        # Fallback test via wevtutil
        try:
            res = subprocess.run(
                ["wevtutil", "qe", channel, "/c:1", "/f:RenderedXml"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if res.returncode == 0:
                return True, None
            err_msg = res.stderr.strip() or res.stdout.strip()
            if "Access is denied" in err_msg or "0x5" in err_msg:
                return False, "Access is denied. Administrator privileges or 'Event Log Readers' group membership required."
            return False, f"wevtutil check returned code {res.returncode}: {err_msg}"
        except Exception as ex:
            return False, f"Failed executing wevtutil: {str(ex)}"

    def fetch_events(self, channel: str, last_record_id: int, max_records: int = 100) -> Tuple[List[str], Optional[str]]:
        if not IS_WINDOWS:
            return [], "Operating system is not Windows."

        xpath = f"*[System[(EventRecordID > {last_record_id})]]" if last_record_id > 0 else "*"

        # Strategy 1: Native wevtapi.dll query
        if self.use_ctypes:
            import ctypes
            from ctypes import wintypes
            # EvtQueryChannelPath = 1; if last_record_id is 0, fetch oldest first or latest
            flags = 1
            h_query = wevtapi.EvtQuery(None, channel, xpath, flags)
            if not h_query:
                err = ctypes.GetLastError()
                if err == 5:
                    return [], "Access is denied (Error 5). Administrator privilege required to read Windows Security log."
                return [], f"EvtQuery failed with error code {err}"

            event_handles = (wintypes.HANDLE * max_records)()
            returned = wintypes.DWORD(0)
            xml_list = []

            try:
                success = wevtapi.EvtNext(
                    h_query,
                    max_records,
                    event_handles,
                    2000,  # 2 second timeout
                    0,
                    ctypes.byref(returned)
                )

                if success and returned.value > 0:
                    for i in range(returned.value):
                        h_ev = event_handles[i]
                        buf_size = wintypes.DWORD(0)
                        prop_count = wintypes.DWORD(0)
                        # First call to get buffer size
                        wevtapi.EvtRender(None, h_ev, 1, 0, None, ctypes.byref(buf_size), ctypes.byref(prop_count))
                        if buf_size.value > 0:
                            buf = ctypes.create_unicode_buffer(buf_size.value // 2 + 1)
                            if wevtapi.EvtRender(None, h_ev, 1, buf_size.value, buf, ctypes.byref(buf_size), ctypes.byref(prop_count)):
                                xml_list.append(buf.value)
                        wevtapi.EvtClose(h_ev)
            finally:
                wevtapi.EvtClose(h_query)

            return xml_list, None

        # Strategy 2: wevtutil subprocess fallback
        try:
            cmd = ["wevtutil", "qe", channel, f"/q:{xpath}", f"/c:{max_records}", "/f:RenderedXml"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode != 0:
                err_text = res.stderr.strip()
                if "Access is denied" in err_text:
                    return [], "Access is denied. Administrator privileges required."
                return [], err_text

            raw_output = res.stdout.strip()
            if not raw_output:
                return [], None

            # Split multiple <Event> XML documents
            events_xml = []
            chunks = raw_output.split("<Event xmlns=")
            for c in chunks:
                if c.strip():
                    events_xml.append("<Event xmlns=" + c if not c.startswith("<Event") else c)

            return events_xml, None
        except Exception as e:
            return [], f"Subprocess fetch failed: {str(e)}"


class SimulatedEventSource(BaseEventSource):
    """
    Simulation event source for automated tests, non-Windows environments,
    and offline presentations without real Security log elevation.
    """
    def __init__(self):
        self.sim_record_id = 1000
        self.pending_scenarios: List[str] = []

    def queue_event_xml(self, xml_content: str):
        """Queue custom event XML for testing."""
        self.pending_scenarios.append(xml_content)

    def test_access(self, channel: str = "Security") -> Tuple[bool, Optional[str]]:
        return True, None

    def fetch_events(self, channel: str, last_record_id: int, max_records: int = 100) -> Tuple[List[str], Optional[str]]:
        if self.pending_scenarios:
            batch = self.pending_scenarios[:max_records]
            self.pending_scenarios = self.pending_scenarios[max_records:]
            return batch, None

        # If no specific events queued, return empty
        return [], None


class WindowsSecurityCollector:
    """
    Background collector service that continuously reads, normalizes,
    and ingests Windows Security Event logs into the PrivilegeGuard AI pipeline.
    """
    _instance: Optional["WindowsSecurityCollector"] = None
    _lock = threading.Lock()

    def __init__(self):
        self.channel = "Security"
        self.polling_interval = 5.0
        self.batch_size = 100
        self.is_running = False
        self.status = "Stopped"
        self.source_type = "Native Windows wevtapi" if IS_WINDOWS else "Simulated Adapter"
        self.error_message: Optional[str] = None
        self.last_poll_timestamp: Optional[datetime] = None
        self.last_record_id: int = 0
        self.total_collected: int = 0
        
        self.worker_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.app = None

        # Select event source adapter
        if IS_WINDOWS:
            self.event_source: BaseEventSource = NativeWindowsEventSource()
        else:
            self.event_source = SimulatedEventSource()

    @classmethod
    def get_instance(cls) -> "WindowsSecurityCollector":
        """Singleton accessor ensuring only one collector worker exists."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def set_event_source(self, source: BaseEventSource, source_name: str = "Custom"):
        """Allow injection of simulated event source for testing."""
        self.event_source = source
        self.source_type = source_name

    def load_checkpoint_from_db(self, app):
        """Restore persistent checkpoint from database."""
        with app.app_context():
            from models import db, CollectorCheckpoint
            try:
                cp = CollectorCheckpoint.query.filter_by(channel=self.channel).first()
                if cp:
                    self.last_record_id = cp.last_record_id
                    self.total_collected = cp.total_events_collected
                    self.polling_interval = cp.polling_interval_seconds
                    self.batch_size = cp.batch_size_limit
                    self.status = cp.status if cp.status != "Running" else "Stopped"  # Reset ungraceful shutdown
                else:
                    # Initialize default checkpoint record
                    cp = CollectorCheckpoint(
                        channel=self.channel,
                        last_record_id=0,
                        status="Stopped",
                        polling_interval_seconds=self.polling_interval,
                        batch_size_limit=self.batch_size,
                        source_type=self.source_type
                    )
                    db.session.add(cp)
                    db.session.commit()
            except Exception as e:
                logger.error(f"Failed loading checkpoint from DB: {e}")

    def save_checkpoint_to_db(self, app, status=None, error_msg=None, new_events_count=0):
        """Persist updated bookmark and collector metrics to database."""
        with app.app_context():
            from models import db, CollectorCheckpoint
            try:
                cp = CollectorCheckpoint.query.filter_by(channel=self.channel).first()
                if not cp:
                    cp = CollectorCheckpoint(channel=self.channel)
                    db.session.add(cp)

                now = datetime.now(timezone.utc)
                cp.last_record_id = self.last_record_id
                cp.last_poll_timestamp = now
                if status:
                    cp.status = status
                    self.status = status
                if error_msg is not None:
                    cp.error_message = error_msg
                    self.error_message = error_msg
                if new_events_count > 0:
                    self.total_collected += new_events_count
                    cp.last_event_timestamp = now
                cp.total_events_collected = self.total_collected


                cp.source_type = self.source_type
                cp.polling_interval_seconds = self.polling_interval
                cp.batch_size_limit = self.batch_size
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed updating checkpoint in DB: {e}")

    def poll_once(self, app) -> Dict[str, Any]:
        """
        Execute a single polling iteration:
        1. Fetch raw XML events > last_record_id
        2. Normalize events via WindowsEventParser
        3. Ingest and persist accepted events
        4. Trigger DetectionEngine and IncidentCorrelationEngine
        5. Advance checkpoint atomically only upon successful persistence
        """
        self.last_poll_timestamp = datetime.now(timezone.utc)
        
        # Step 1: Verify channel access
        accessible, access_err = self.event_source.test_access(self.channel)
        if not accessible:
            self.error_message = access_err
            self.status = "Access Denied" if "Access is denied" in (access_err or "") else "Error"
            self.save_checkpoint_to_db(app, status=self.status, error_msg=self.error_message)
            return {
                "success": False,
                "error": access_err,
                "status": self.status,
                "collected_count": 0
            }

        # Step 2: Fetch events batch
        xml_events, fetch_err = self.event_source.fetch_events(
            self.channel,
            self.last_record_id,
            self.batch_size
        )

        if fetch_err:
            self.error_message = fetch_err
            self.status = "Error"
            self.save_checkpoint_to_db(app, status="Error", error_msg=fetch_err)
            return {
                "success": False,
                "error": fetch_err,
                "status": self.status,
                "collected_count": 0
            }

        if not xml_events:
            # Poll succeeded with 0 new events
            self.error_message = None
            self.status = "Running"
            self.save_checkpoint_to_db(app, status="Running", error_msg=None)
            return {
                "success": True,
                "status": "Running",
                "collected_count": 0,
                "message": "No new events in channel."
            }

        # Step 3: Parse and normalize events
        normalized_records = []
        highest_record_id = self.last_record_id

        for xml_str in xml_events:
            parsed = WindowsEventParser.parse_xml_to_dict(xml_str)
            if parsed:
                norm = WindowsEventParser.normalize_event(parsed)
                if norm:
                    normalized_records.append(norm)
                    rec_id = parsed.get("record_id", 0)
                    if rec_id > highest_record_id:
                        highest_record_id = rec_id

        if not normalized_records:
            if highest_record_id > self.last_record_id:
                self.last_record_id = highest_record_id
                self.save_checkpoint_to_db(app, status="Running", error_msg=None)
            return {
                "success": True,
                "status": "Running",
                "collected_count": 0,
                "message": "Events parsed had no actionable security attributes."
            }

        # Step 4: Ingest and persist events through application pipeline
        with app.app_context():
            ingest_result = IngestionService._process_records(normalized_records)

            if not ingest_result.get("success", False):
                err = ingest_result.get("error_message", "Ingestion commit failed")
                self.error_message = err
                self.save_checkpoint_to_db(app, status="Error", error_msg=err)
                return {
                    "success": False,
                    "error": err,
                    "collected_count": 0
                }

            accepted_count = ingest_result.get("accepted_count", 0)
            accepted_events = ingest_result.get("accepted_events", [])

            # Step 5: Automatically trigger detection & incident correlation on newly accepted events
            alerts_count = 0
            incidents_count = 0
            if accepted_count > 0:
                from models import SecurityEvent
                # Fetch recent events for context
                all_recent = SecurityEvent.query.order_by(SecurityEvent.timestamp.asc()).all()
                engine = DetectionEngine(Config())
                alerts = engine.run_detection(all_recent)
                alerts_count = len(alerts)
                if alerts:
                    incidents = IncidentCorrelationEngine.correlate_alerts(alerts, Config())
                    incidents_count = len(incidents)

            # Step 6: Advance checkpoint ONLY after successful database write
            self.last_record_id = highest_record_id
            self.error_message = None
            self.status = "Running"
            self.save_checkpoint_to_db(
                app,
                status="Running",
                error_msg=None,
                new_events_count=accepted_count
            )

        return {
            "success": True,
            "status": "Running",
            "collected_count": accepted_count,
            "total_processed": len(normalized_records),
            "alerts_generated": alerts_count,
            "incidents_correlated": incidents_count,
            "checkpoint": self.last_record_id
        }

    def _worker_loop(self):
        """Continuous background collection loop."""
        logger.info(f"Windows Security Collector thread started (Polling every {self.polling_interval}s).")
        while not self.stop_event.is_set():
            try:
                self.poll_once(self.app)
            except Exception as e:
                logger.exception(f"Unexpected error in collector worker loop: {e}")
                self.error_message = str(e)
                self.status = "Error"
                if self.app:
                    self.save_checkpoint_to_db(self.app, status="Error", error_msg=str(e))

            # Sleep interruptible
            self.stop_event.wait(self.polling_interval)

        logger.info("Windows Security Collector thread stopped gracefully.")

    def start(self, app, channel="Security", polling_interval=5.0, batch_size=100) -> Dict[str, Any]:
        """Start the background collection worker."""
        with self._lock:
            if self.is_running:
                return {
                    "success": True,
                    "message": "Collector is already running.",
                    "status": self.status,
                    "checkpoint": self.last_record_id
                }

            self.app = app
            self.channel = channel
            self.polling_interval = float(polling_interval)
            self.batch_size = int(batch_size)

            # Load checkpoint from DB
            self.load_checkpoint_from_db(app)

            # Verify access first
            accessible, access_err = self.event_source.test_access(self.channel)
            if not accessible:
                self.status = "Access Denied" if "Access is denied" in (access_err or "") else "Error"
                self.error_message = access_err
                self.save_checkpoint_to_db(app, status=self.status, error_msg=access_err)
                return {
                    "success": False,
                    "status": self.status,
                    "error": access_err,
                    "message": "Collector could not start due to permission or channel error."
                }

            self.is_running = True
            self.status = "Running"
            self.stop_event.clear()
            self.save_checkpoint_to_db(app, status="Running", error_msg=None)

            self.worker_thread = threading.Thread(
                target=self._worker_loop,
                name="WindowsSecurityCollectorThread",
                daemon=True
            )
            self.worker_thread.start()

            return {
                "success": True,
                "message": f"Collector started on channel '{self.channel}'",
                "status": "Running",
                "polling_interval": self.polling_interval,
                "checkpoint": self.last_record_id
            }

    def stop(self) -> Dict[str, Any]:
        """Stop the background collection worker gracefully."""
        with self._lock:
            if not self.is_running:
                return {
                    "success": True,
                    "message": "Collector is already stopped.",
                    "status": self.status
                }

            self.is_running = False
            self.status = "Stopped"
            self.stop_event.set()

            if self.worker_thread and self.worker_thread.is_alive():
                self.worker_thread.join(timeout=3.0)

            if self.app:
                self.save_checkpoint_to_db(self.app, status="Stopped")

            return {
                "success": True,
                "message": "Collector stopped gracefully.",
                "status": "Stopped",
                "checkpoint": self.last_record_id
            }

    def get_status(self) -> Dict[str, Any]:
        """Return the current collector health, status, and bookmark metrics."""
        return {
            "is_running": self.is_running,
            "status": self.status,
            "channel": self.channel,
            "source_type": self.source_type,
            "polling_interval_seconds": self.polling_interval,
            "batch_size_limit": self.batch_size,
            "last_record_id": self.last_record_id,
            "last_poll_timestamp": self.last_poll_timestamp.isoformat() if self.last_poll_timestamp else None,
            "total_events_collected": self.total_collected,
            "error_message": self.error_message
        }
