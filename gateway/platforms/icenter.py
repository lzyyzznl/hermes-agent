"""
iCenter (ZTE enterprise messaging) platform adapter.

Protocol: WebSocket long-connection with SSE-format streaming.
Authentication: secretKey in URL query parameter.
Ported from OpenClaw's TypeScript implementation.
"""

import asyncio
import json
import logging
import os
import platform as _platform
import shutil
import socket
import subprocess
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, MessageEvent, MessageType, SendResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_WEBSOCKET_URL = (
    "wss://igpt.dt.zte.com.cn/zte-icenter-igpt-coclaw/clawbot"
)
_ICENTER_SERVICE_BASE_URL = (
    os.getenv("ICENTER_SERVICE_URL", "https://igpt.dt.zte.com.cn")
)
_ICENTER_KEYS_PATH = (
    os.getenv("ICENTER_KEYS_PATH", "/zte-icenter-igpt-coclaw/bot-service/keys")
)
_HEARTBEAT_INTERVAL = 30          # seconds
_PONG_TIMEOUT_FACTOR = 1.5       # pong timeout = heartbeat * factor
_INITIAL_RECONNECT_DELAY = 1.0   # seconds
_MAX_RECONNECT_DELAY = 60.0      # seconds
_RECONNECT_BACKOFF_MULTIPLIER = 2.0
_MAX_MESSAGE_LENGTH = 4000
_DEDUP_CACHE_SIZE = 2048
_DEDUP_TTL_SECONDS = 86400       # 24 hours


# ---------------------------------------------------------------------------
# UAC credential helpers (cli-uac)
# ---------------------------------------------------------------------------

def _get_uac_credentials() -> Optional[Tuple[str, str]]:
    """Get empno and auth token via cli-uac binary.

    Looks for cli-uac in: adapter directory → system PATH.
    Returns (empno, token) or None if unavailable.
    """
    # Prefer local copy in adapter directory
    local_cli = os.path.join(os.path.dirname(__file__), "cli-uac")
    cli_uac = local_cli if os.path.isfile(local_cli) else shutil.which("cli-uac")
    if not cli_uac:
        return None

    try:
        result = subprocess.run(
            [cli_uac],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        data = json.loads(result.stdout.strip())
        empno = data.get("coclaw_empno", "").strip()
        token = data.get("coclaw_token", "").strip()
        if empno and token:
            return empno, token
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        pass
    return None


async def _create_icenter_key(empno: str, token: str) -> Optional[str]:
    """Call iCenter bot-service API to create a secretKey.

    POST {service_url}{keys_path}
    Headers: X-Emp-No, X-Auth-Value
    Body: {"botId": empno}
    Returns secretKey on success, None on failure.
    """
    try:
        import aiohttp
        import ssl
    except ImportError:
        return None

    base = _ICENTER_SERVICE_BASE_URL.rstrip("/")
    url = f"{base}{_ICENTER_KEYS_PATH}"
    headers = {
        "Content-Type": "application/json",
        "X-Emp-No": empno,
        "X-Auth-Value": token,
    }
    payload = {"botId": empno}

    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        conn = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=conn) as session:
            async with session.post(url, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                data = await resp.json()
                code = (data.get("code") or {}).get("code", "")
                secret_key = data.get("bo")
                if code == "0000" and secret_key:
                    logger.info("[iCenter] Auto-created secretKey for empno=%s", empno)
                    return secret_key
                msg = (data.get("code") or {}).get("msg", "unknown error")
                logger.warning("[iCenter] Key creation failed: %s", msg)
                return None
    except Exception as exc:
        logger.warning("[iCenter] Key creation request failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Requirement check
# ---------------------------------------------------------------------------

def check_icenter_requirements() -> bool:
    """Check if iCenter can be used.

    Requires either:
    - ICENTER_SECRET_KEY env var, OR
    - cli-uac binary in adapter dir or system PATH (for auto key creation)
    AND aiohttp installed.
    """
    try:
        import aiohttp  # noqa: F401
    except ImportError:
        return False
    if os.getenv("ICENTER_SECRET_KEY"):
        return True
    local_cli = os.path.join(os.path.dirname(__file__), "cli-uac")
    return os.path.isfile(local_cli) or shutil.which("cli-uac") is not None


# ---------------------------------------------------------------------------
# Dedup cache (thread-safe, bounded, with TTL)
# ---------------------------------------------------------------------------

class _DedupCache:
    """Bounded LRU cache for message deduplication."""

    def __init__(self, maxsize: int = _DEDUP_CACHE_SIZE, ttl: float = _DEDUP_TTL_SECONDS):
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._maxsize = maxsize
        self._ttl = ttl

    def is_duplicate(self, msg_id: Any) -> bool:
        key = str(msg_id)
        now = time.time()
        if key in self._cache:
            ts = self._cache[key]
            if self._ttl <= 0 or now - ts < self._ttl:
                # Move to end (most recently seen)
                self._cache.move_to_end(key)
                return True
            # Expired — remove and re-insert below
            del self._cache[key]
        self._cache[key] = now
        while len(self._cache) > self._maxsize:
            self._cache.popitem(last=False)
        return False


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

class ICenterAdapter(BasePlatformAdapter):
    """iCenter enterprise messaging adapter (WebSocket)."""

    MAX_MESSAGE_LENGTH = _MAX_MESSAGE_LENGTH

    # =====================================================================
    # Lifecycle
    # =====================================================================

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.ICENTER)
        extra = config.extra or {}

        self._secret_key: str = extra.get("secret_key", "") or os.getenv("ICENTER_SECRET_KEY", "")
        self._websocket_url: str = extra.get("websocket_url", "") or os.getenv(
            "ICENTER_WEBSOCKET_URL", _DEFAULT_WEBSOCKET_URL
        )
        self._account_id: str = extra.get("account_id", "") or os.getenv("ICENTER_ACCOUNT_ID", "")

        # Connection state
        self._session: Optional[Any] = None   # aiohttp.ClientSession
        self._ws: Optional[Any] = None         # aiohttp.ClientWebSocketResponse
        self._running = False
        self._connected = False
        self._receive_task: Optional[asyncio.Task] = None

        # Reconnection state
        self._reconnect_delay = _INITIAL_RECONNECT_DELAY
        self._is_reconnecting = False

        # Message deduplication
        self._dedup = _DedupCache()

        # Inbound metadata: chatUuid → {stream, msgId, topicId, digitalEmpNo}
        self._inbound_meta: Dict[str, Dict[str, Any]] = {}

    # -----------------------------------------------------------------
    # connect
    # -----------------------------------------------------------------

    async def connect(self) -> bool:
        """Connect to iCenter WebSocket.

        Authentication priority:
        1. ICENTER_SECRET_KEY env var (explicit config)
        2. Auto-create via cli-uac + bot-service API
        """
        if not self._secret_key:
            # Try auto key creation via cli-uac
            uac = _get_uac_credentials()
            if uac:
                empno, token = uac
                logger.info("[iCenter] No secretKey configured, auto-creating via cli-uac (empno=%s)", empno)
                secret_key = await _create_icenter_key(empno, token)
                if secret_key:
                    self._secret_key = secret_key
                    if not self._account_id:
                        self._account_id = empno
                else:
                    logger.error("[iCenter] Auto key creation failed")
                    return False
            else:
                logger.error("[iCenter] No ICENTER_SECRET_KEY set and cli-uac unavailable")
                return False

        try:
            self._running = True
            await self._connect_once()
            self._mark_connected()
            logger.info("[iCenter] Connected to %s", self._websocket_url)
            return True
        except Exception as exc:
            self._running = False
            logger.error("[iCenter] Connection failed: %s", exc)
            return False

    async def _connect_once(self) -> None:
        """Establish a single WebSocket connection (no retry loop)."""
        import aiohttp
        import ssl

        url = f"{self._websocket_url}?key={self._secret_key}"
        headers = {}
        if self._account_id:
            headers["X-Emp-No"] = self._account_id
        headers["X-Hostname"] = socket.gethostname()
        headers["X-Platform"] = _platform.system().lower()
        headers["X-Arch"] = _platform.machine()

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        if self._session is None or self._session.closed:
            conn = aiohttp.TCPConnector(ssl=ssl_ctx)
            self._session = aiohttp.ClientSession(connector=conn)

        logger.info("[iCenter] Connecting to %s", self._websocket_url)
        self._ws = await self._session.ws_connect(
            url,
            headers=headers,
            heartbeat=_HEARTBEAT_INTERVAL,  # aiohttp sends pings, responds to pongs
            receive_timeout=None,
            autoping=True,
        )

        # Reset backoff on success
        self._reconnect_delay = _INITIAL_RECONNECT_DELAY
        self._connected = True

        # Start receive task (heartbeat managed by aiohttp internally)
        self._receive_task = asyncio.create_task(self._receive_loop())

    # -----------------------------------------------------------------
    # disconnect
    # -----------------------------------------------------------------

    async def disconnect(self) -> None:
        """Disconnect from iCenter."""
        self._running = False
        self._connected = False
        self._is_reconnecting = False

        for task in (self._receive_task,):
            if task and not task.done():
                task.cancel()
        self._receive_task = None

        if self._ws and not self._ws.closed:
            await self._ws.close()
        self._ws = None

        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

        self._mark_disconnected()
        logger.info("[iCenter] Disconnected")

    # -----------------------------------------------------------------
    # Receive loop
    # -----------------------------------------------------------------

    async def _receive_loop(self) -> None:
        """Process incoming WebSocket messages.

        Uses aiohttp's async iterator pattern. All TEXT messages are
        dispatched to background tasks (non-blocking) so the receive loop
        stays responsive for subsequent messages.
        """
        import aiohttp

        if not self._ws:
            return
        try:
            async for msg in self._ws:
                if not self._running:
                    break

                if msg.type == aiohttp.WSMsgType.TEXT:
                    # Non-blocking dispatch: each message gets its own task
                    # so the receive loop continues immediately
                    task = asyncio.create_task(self._handle_raw_message(msg.data))
                    task.add_done_callback(self._on_task_done)

                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error("[iCenter] WebSocket error: %s", msg)
                    break

                elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED):
                    logger.warning("[iCenter] WebSocket closed (type=%s)", msg.type)
                    break

                # PING/PONG/BINARY are handled by aiohttp internally or ignored

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("[iCenter] Receive loop error: %s", exc, exc_info=True)
        finally:
            self._connected = False
            if self._running:
                await self._schedule_reconnect()

    @staticmethod
    def _on_task_done(task: asyncio.Task) -> None:
        """Callback to log unhandled exceptions from message processing tasks."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            logger.error("[iCenter] Message processing task failed: %s", exc, exc_info=exc)

    async def _handle_raw_message(self, raw: str) -> None:
        """Parse and dispatch an inbound iCenter message.

        Wraps the entire processing in try/except to prevent any error
        from crashing the task silently (OpenClaw pattern).
        """
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("[iCenter] Invalid JSON: %s", raw[:200])
            return

        try:
            msg_id = data.get("msgId")
            text = data.get("text", "")
            chat_uuid = data.get("chatUuid", "")
            topic_id = data.get("topicId")
            sender_name = data.get("senderCName", "")
            sender_emp_no = data.get("digitalEmpNo", "")
            group_id = data.get("groupId", "")
            stream = data.get("stream", False)

            logger.info(
                "[iCenter] Inbound msgId=%s chatUuid=%s sender=%s(%s) text=%.80s group=%s",
                msg_id, chat_uuid, sender_name, sender_emp_no,
                text[:80] if text else "(empty)", group_id,
            )

            # Dedup
            if msg_id is not None and self._dedup.is_duplicate(msg_id):
                logger.debug("[iCenter] Duplicate msgId=%s, skipping", msg_id)
                return

            # Skip empty messages
            if not text or not text.strip():
                logger.debug("[iCenter] Empty text in msgId=%s, skipping", msg_id)
                return

            # Skip bot's own messages (prevent echo loop)
            if sender_emp_no and self._account_id and sender_emp_no == self._account_id:
                logger.debug("[iCenter] Skipping own message msgId=%s", msg_id)
                return

            # Store inbound metadata for reply routing
            if chat_uuid:
                self._inbound_meta[chat_uuid] = {
                    "stream": stream,
                    "msgId": msg_id,
                    "topicId": topic_id,
                    "digitalEmpNo": sender_emp_no,
                }

            # Determine chat type
            chat_type = "group" if group_id else "dm"
            chat_id = chat_uuid or str(msg_id)

            # Build SessionSource
            source = self.build_source(
                chat_id=chat_id,
                chat_type=chat_type,
                user_id=sender_emp_no,
                user_name=sender_name,
                thread_id=str(topic_id) if topic_id else None,
            )

            # Build and dispatch MessageEvent
            event = MessageEvent(
                message_type=MessageType.TEXT,
                text=text.strip(),
                source=source,
                raw_message=data,
            )
            await self.handle_message(event)

        except Exception as exc:
            logger.error("[iCenter] Error processing message: %s", exc, exc_info=True)

    # -----------------------------------------------------------------
    # Reconnection (with dedup guard, like OpenClaw's isReconnecting)
    # -----------------------------------------------------------------

    async def _schedule_reconnect(self) -> None:
        """Schedule reconnection with exponential backoff.

        Uses _is_reconnecting flag to prevent duplicate reconnection
        attempts (mirrors OpenClaw's scheduleReconnect pattern).
        """
        if not self._running or self._is_reconnecting:
            return

        self._is_reconnecting = True

        try:
            # Cancel old tasks
            for task in (self._receive_task,):
                if task and not task.done():
                    task.cancel()
            self._receive_task = None

            # Close old WebSocket
            if self._ws and not self._ws.closed:
                try:
                    await self._ws.close()
                except Exception:
                    pass
            self._ws = None

            logger.info("[iCenter] Reconnecting in %.1fs...", self._reconnect_delay)
            await asyncio.sleep(self._reconnect_delay)
            self._reconnect_delay = min(
                self._reconnect_delay * _RECONNECT_BACKOFF_MULTIPLIER,
                _MAX_RECONNECT_DELAY,
            )

            # Attempt reconnection with retry
            attempt = 0
            while self._running:
                attempt += 1
                try:
                    await self._connect_once()
                    logger.info("[iCenter] Reconnected successfully (attempt %d)", attempt)
                    return
                except Exception as exc:
                    logger.warning(
                        "[iCenter] Reconnect attempt %d failed: %s; retrying in %.1fs",
                        attempt, exc, self._reconnect_delay,
                    )
                    await asyncio.sleep(self._reconnect_delay)
                    self._reconnect_delay = min(
                        self._reconnect_delay * _RECONNECT_BACKOFF_MULTIPLIER,
                        _MAX_RECONNECT_DELAY,
                    )
        finally:
            self._is_reconnecting = False

    async def _reconnect(self) -> None:
        """Legacy reconnect entry point — delegates to _schedule_reconnect."""
        await self._schedule_reconnect()

    # =====================================================================
    # Outbound
    # =====================================================================

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a text message via iCenter WebSocket."""
        if not self._ws or self._ws.closed:
            return SendResult(success=False, error="WebSocket not connected")

        formatted = self.format_message(content)
        chunks = self.truncate_message(formatted, self.MAX_MESSAGE_LENGTH)

        sse_mode = not (metadata or {}).get("_standalone", False)
        last_ok = True
        for chunk in chunks:
            ok = await self._send_envelope(chat_id, chunk, metadata, sse=sse_mode)
            if not ok:
                last_ok = False

        return SendResult(success=last_ok)

    async def _send_envelope(
        self,
        chat_id: str,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
        *,
        sse: bool = True,
    ) -> bool:
        """Send a message via SSE or JSON envelope format.

        Args:
            sse: True for SSE format (conversation streaming), False for
                 one-shot JSON envelope (standalone tool sends).
        """
        if not self._ws or self._ws.closed:
            return False

        meta = self._inbound_meta.get(chat_id, {})
        msg_id = ""
        if metadata and metadata.get("msgId"):
            msg_id = str(metadata["msgId"])
        elif meta.get("msgId"):
            msg_id = str(meta["msgId"])

        try:
            if sse:
                payload: Dict[str, Any] = {
                    "chatUuid": chat_id,
                    "finishReason": "stop",
                    "result": text,
                }
                if msg_id:
                    payload["messageId"] = msg_id
                await self._ws.send_str(f"data: {json.dumps(payload, ensure_ascii=False)}")
                await self._ws.send_str("data: [DONE]")
                logger.debug("[iCenter] Sent SSE message to %s (%d chars)", chat_id, len(text))
            else:
                envelope: Dict[str, Any] = {
                    "bo": {
                        "chatUuid": chat_id,
                        "result": text,
                        "msgType": "cron",
                    },
                    "code": {
                        "code": "0000",
                        "msg": "Success",
                        "msgId": "RetCode.Success",
                    },
                }
                if msg_id:
                    envelope["bo"]["messageId"] = msg_id
                await self._ws.send_str(json.dumps(envelope, ensure_ascii=False))
                logger.debug("[iCenter] Sent JSON envelope to %s (%d chars)", chat_id, len(text))
            return True
        except Exception as exc:
            logger.error("[iCenter] Send failed: %s", exc)
            return False

    async def send_streaming_token(
        self,
        chat_uuid: str,
        token: str,
        done: bool = False,
    ) -> bool:
        """Send a streaming token via SSE format over WebSocket (Phase 2)."""
        if not self._ws or self._ws.closed:
            return False

        streaming_data = {
            "chatUuid": chat_uuid,
            "finishReason": "stop" if done else "",
            "result": token,
        }
        try:
            await self._ws.send_str(f"data: {json.dumps(streaming_data, ensure_ascii=False)}")
            if done:
                await self._ws.send_str("data: [DONE]")
            return True
        except Exception as exc:
            logger.error("[iCenter] Streaming send failed: %s", exc)
            return False

    # -----------------------------------------------------------------
    # Stubs
    # -----------------------------------------------------------------

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        """iCenter has no typing indicator."""

    async def get_chat_info(self, chat_id: str) -> dict:
        """Return basic chat info."""
        meta = self._inbound_meta.get(chat_id, {})
        return {
            "name": chat_id,
            "type": "group" if meta.get("groupId") else "dm",
            "chat_id": chat_id,
        }

    async def send_image(
        self,
        chat_id: str,
        image_url: str,
        caption: str = "",
    ) -> SendResult:
        """Send image as text link (iCenter image upload via local client not supported in Phase 1)."""
        text = image_url
        if caption:
            text = f"{caption}\n{image_url}"
        return await self.send(chat_id, text)

    async def send_image_file(
        self,
        chat_id: str,
        path: str,
        caption: str = "",
    ) -> SendResult:
        """Send image file path as text (Phase 1)."""
        text = path
        if caption:
            text = f"{caption}\n{path}"
        return await self.send(chat_id, text)
