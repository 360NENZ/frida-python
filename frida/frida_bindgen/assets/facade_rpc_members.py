def _setup(self) -> None:
    self.exports_sync = _ScriptExports(self)
    self._message_handlers: List[ScriptMessageCallback] = []
    self._log_handler: Callable[[str, str], None] = self.default_log_handler
    self._pending: Dict[str, Callable[[Any, Optional[Exception]], None]] = {}
    self._cond = threading.Condition()
    self._impl.on("message", self._on_message)
    self._impl.on("destroyed", self._on_destroyed)

@property
def exports(self) -> "_ScriptExports":
    return self.exports_sync

def on(self, signal: str, callback: Callable[..., Any]) -> None:
    if signal == "message":
        self._message_handlers.append(callback)
    else:
        self._impl.on(signal, _make_signal_handler(callback))

def off(self, signal: str, callback: Callable[..., Any]) -> None:
    if signal == "message":
        self._message_handlers.remove(callback)
    else:
        self._impl.off(signal, callback)

def get_log_handler(self) -> Callable[[str, str], None]:
    return self._log_handler

def set_log_handler(self, handler: Callable[[str, str], None]) -> None:
    self._log_handler = handler

def default_log_handler(self, level: str, text: str) -> None:
    if level == "info":
        print(text, file=sys.stdout)
    else:
        print(text, file=sys.stderr)

def list_exports_sync(self) -> List[str]:
    return self._rpc_request(["list"])

def list_exports(self) -> List[str]:
    return self.list_exports_sync()

def _list_exports(self) -> List[str]:
    return self.list_exports_sync()

def _rpc_request(self, args: Any, data: Optional[bytes] = None) -> Any:
    outcome: Dict[str, Any] = {}
    cond = self._cond

    def complete(value: Any, error: Optional[Exception]) -> None:
        with cond:
            outcome["value"] = value
            outcome["error"] = error
            cond.notify_all()

    with cond:
        request_id = uuid.uuid4().hex
        self._pending[request_id] = complete

    if self._impl.is_destroyed():
        self._on_destroyed()
    else:
        self.post([request_id] + list(args), data)

    with cond:
        while not outcome:
            cond.wait()

    if outcome["error"] is not None:
        raise outcome["error"]
    return outcome["value"]

def _on_message(self, raw_message: str, data: Optional[bytes]) -> None:
    message = json.loads(raw_message)
    mtype = message["type"]
    payload = message.get("payload")
    if mtype == "log":
        self._log_handler(message["level"], payload)
    elif (mtype == "send" and isinstance(payload, list) and len(payload) >= 3
          and isinstance(payload[0], str) and payload[0] in self._pending
          and payload[1] in ("ok", "error")):
        self._on_rpc_message(payload[0], payload[1], payload[2:], data)
    else:
        for handler in list(self._message_handlers):
            try:
                handler(message, data)
            except Exception:
                traceback.print_exc()

def _on_destroyed(self) -> None:
    while True:
        with self._cond:
            pending_ids = list(self._pending.keys())
            complete = self._pending.pop(pending_ids[0]) if pending_ids else None
        if complete is None:
            break
        complete(None, _frida.InvalidOperationError("script has been destroyed"))

def _on_rpc_message(self, request_id: str, operation: str, params: List[Any], data: Optional[Any]) -> None:
    if operation not in ("ok", "error"):
        return
    complete = self._pending.pop(request_id, None)
    if complete is None:
        return
    if operation == "error":
        complete(None, RPCException(*params[0:3]))
    elif data is not None:
        complete((params[1], data) if len(params) > 1 else data, None)
    else:
        complete(params[0], None)
