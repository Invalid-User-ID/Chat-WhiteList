import json
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path

from pynicotine.pluginsystem import BasePlugin, returncode
from pynicotine.config import config


class Plugin(BasePlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.plugin_dir = Path(__file__).resolve().parent
        self.backup_dir = self.plugin_dir / "backup"
        self.backup_file = self.backup_dir / "whitelist_backup.json"
        self._lock = threading.RLock()

        defaults = {
            "enabled": True,
            "whitelist": [],
            "allow_private_messages": True,
            "preview_logging": False,
            "preview_length": 50,
            "blocked_user_log_delay": 30,
            "backup_enabled": True,
            "backup_interval": 60,
        }

        existing = getattr(self, "settings", None)
        if isinstance(existing, dict):
            merged = dict(defaults)
            merged.update(existing)
            self.settings = merged
        else:
            self.settings = dict(defaults)

        self.metasettings = {
            "enabled": {"description": "Enable whitelist filtering", "type": "bool"},
            "whitelist": {"description": "User Whitelist", "type": "list string"},
            "allow_private_messages": {"description": "Allow Private PMs", "type": "bool"},
            "preview_logging": {"description": "Log Blocked Messages", "type": "bool"},
            "preview_length": {"description": "Log Preview Length", "type": "int", "minimum": 0, "maximum": 1000},
            "blocked_user_log_delay": {"description": "Log Delay (Secs)", "type": "int", "minimum": 1, "maximum": 1000},
            "backup_enabled": {"description": "Enable Periodic JSON Backup", "type": "bool"},
            "backup_interval": {"description": "Backup Interval (Minutes)", "type": "int", "minimum": 1, "maximum": 1440},
        }

        self.commands = {
            "wla": {"callback": self.cmd_add, "parameters": ["<username>"]},
            "wlr": {"callback": self.cmd_remove, "parameters": ["<username>"]},
            "wll": {"callback": self.cmd_list},
            "wli": {"callback": self.cmd_import, "description": "Import WhiteList from JSON backup."},
        }

        self._whitelist_set: set[str] = set()
        self._blocked_log_ts: dict[str, float] = {}
        self._backup_timer: threading.Timer | None = None

        self._enabled: bool = True
        self._allow_private_messages: bool = True
        self._preview_logging: bool = False
        self._preview_length: int = 50
        self._blocked_user_log_delay: int = 30
        self._backup_enabled: bool = True
        self._backup_interval_secs: int = 60 * 60

    def _log_error(self, context: str, exc: BaseException, include_traceback: bool = False) -> None:
        msg = f"{context}: {type(exc).__name__}: {exc}"

        if include_traceback:
            self.log(f"{msg}\n{traceback.format_exc()}")
        else:
            self.log(msg)

    def _coerce_bool(self, value, default: bool) -> bool:
        if isinstance(value, bool):
            return value

        if isinstance(value, (int, float)):
            return bool(value)

        if isinstance(value, str):
            v = value.strip().lower()

            if v in ("1", "true", "yes", "y", "on", "enable", "enabled"):
                return True

            if v in ("0", "false", "no", "n", "off", "disable", "disabled"):
                return False

        return default

    def _coerce_int(self, value, default: int) -> int:
        if isinstance(value, bool):
            return default

        if isinstance(value, int):
            return value

        if isinstance(value, float):
            return int(value)

        if isinstance(value, str):
            try:
                return int(value.strip(), 10)
            except ValueError:
                return default

        return default

    def _clamp_int(self, key: str, value: int) -> int:
        meta = self.metasettings.get(key)

        if not meta or meta.get("type") != "int":
            return value

        minimum = meta.get("minimum")
        maximum = meta.get("maximum")

        if minimum is not None:
            try:
                value = max(value, int(minimum))
            except (TypeError, ValueError):
                pass

        if maximum is not None:
            try:
                value = min(value, int(maximum))
            except (TypeError, ValueError):
                pass

        return value

    def _coerce_list_string(self, value, default: list[str]) -> list[str]:
        if not isinstance(value, list):
            return list(default)

        out: list[str] = []

        for item in value:
            if isinstance(item, str):
                s = item.strip()

                if s:
                    out.append(s)

        return out

    def _sanitize_settings(self) -> None:
        with self._lock:
            self.settings["enabled"] = self._coerce_bool(self.settings.get("enabled"), True)
            self.settings["allow_private_messages"] = self._coerce_bool(self.settings.get("allow_private_messages"), True)
            self.settings["preview_logging"] = self._coerce_bool(self.settings.get("preview_logging"), False)
            self.settings["backup_enabled"] = self._coerce_bool(self.settings.get("backup_enabled"), True)

            self.settings["preview_length"] = self._clamp_int(
                "preview_length",
                self._coerce_int(self.settings.get("preview_length"), 50)
            )

            self.settings["blocked_user_log_delay"] = self._clamp_int(
                "blocked_user_log_delay",
                self._coerce_int(self.settings.get("blocked_user_log_delay"), 30)
            )

            self.settings["backup_interval"] = self._clamp_int(
                "backup_interval",
                self._coerce_int(self.settings.get("backup_interval"), 60)
            )

            whitelist = self._coerce_list_string(self.settings.get("whitelist"), [])
            self.settings["whitelist"] = sorted(set(whitelist))

    def _refresh_cached_settings(self) -> None:
        with self._lock:
            self._enabled = bool(self.settings.get("enabled", True))
            self._allow_private_messages = bool(self.settings.get("allow_private_messages", True))
            self._preview_logging = bool(self.settings.get("preview_logging", False))
            self._preview_length = int(self.settings.get("preview_length", 50))
            self._blocked_user_log_delay = int(self.settings.get("blocked_user_log_delay", 30))
            self._backup_enabled = bool(self.settings.get("backup_enabled", True))
            self._backup_interval_secs = max(1, int(self.settings.get("backup_interval", 60))) * 60

    def init(self):
        self._sanitize_settings()
        self._refresh_cached_settings()
        self._rebuild_whitelist_from_settings()

        threading.Timer(2.0, self._start_backup_timer).start()

    def stop(self):
        with self._lock:
            if self._backup_timer:
                self._backup_timer.cancel()
                self._backup_timer = None

    def settings_changed(self, before, after, change):
        self._sanitize_settings()
        self._refresh_cached_settings()
        self._rebuild_whitelist_from_settings()
        self._start_backup_timer()

    def save_settings(self):
        self._sanitize_settings()
        self._refresh_cached_settings()

        try:
            plugin_name = (
                getattr(self, "internal_name", None)
                or getattr(self, "name", None)
                or getattr(self, "__module__", None)
                or self.__class__.__name__
            )

            config.sections.setdefault("plugins", {})
            config.sections["plugins"][plugin_name] = dict(self.settings)
            config.write_configuration()

        except OSError as e:
            self._log_error("Failed to save settings (OS error)", e)

        except Exception as e:
            self._log_error("Failed to save settings (unexpected)", e, include_traceback=True)

    def _get_self_username(self) -> str | None:
        try:
            user = self.core.users.login_username

            if isinstance(user, str):
                user = user.strip()
                return user or None

        except AttributeError:
            return None

        except Exception:
            return None

        return None

    def _start_backup_timer(self):
        with self._lock:
            if self._backup_timer:
                self._backup_timer.cancel()
                self._backup_timer = None

            if not self._backup_enabled:
                return

            timer = threading.Timer(self._backup_interval_secs, self._scheduled_backup)
            timer.daemon = True
            self._backup_timer = timer
            timer.start()

    def _scheduled_backup(self):
        try:
            self.save_to_json()
        finally:
            self._start_backup_timer()

    def save_to_json(self):
        with self._lock:
            whitelist_snapshot = sorted(self._whitelist_set)

        data = {
            "whitelist": whitelist_snapshot,
            "last_backup": datetime.now().isoformat(timespec="seconds"),
        }

        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            self.backup_file.write_text(
                json.dumps(data, indent=4, ensure_ascii=False),
                encoding="utf-8"
            )
            self.log("Automatic backup successful.")

        except PermissionError as e:
            self._log_error("Backup failed (permission denied)", e)

        except OSError as e:
            self._log_error("Backup failed (OS error)", e)

        except Exception as e:
            self._log_error("Backup failed (unexpected)", e, include_traceback=True)

    def _rebuild_whitelist_from_settings(self):
        with self._lock:
            whitelist = self.settings.get("whitelist", [])
            self._whitelist_set = set(whitelist) if isinstance(whitelist, list) else set()
            self.settings["whitelist"] = sorted(self._whitelist_set)

    def _update_and_save(self):
        with self._lock:
            self.settings["whitelist"] = sorted(self._whitelist_set)

        self.save_settings()

    def incoming_public_chat_event(self, room, user, line):
        if not self._enabled:
            return None

        return self._block_check(user, f"room '{room}'", line)

    def incoming_private_chat_event(self, user, line):
        if not self._enabled or self._allow_private_messages:
            return None

        return self._block_check(user, "private chat", line)

    def _block_check(self, user: str, context: str, line):
        me = self._get_self_username()

        if me and user == me:
            return None

        with self._lock:
            if user in self._whitelist_set:
                return None

            if self._preview_logging:
                now = time.time()
                last = self._blocked_log_ts.get(user, 0.0)

                if now - last >= self._blocked_user_log_delay:
                    preview = self._make_preview(line)
                    self.log(f"Blocked {context} from '{user}'{preview}")
                    self._blocked_log_ts[user] = now

        return returncode["zap"]

    def _make_preview(self, line) -> str:
        if not line or self._preview_length <= 0:
            return ""

        clean = " ".join(str(line).split())

        if len(clean) > self._preview_length:
            if self._preview_length <= 3:
                return ' — "..."'

            return f' — "{clean[:self._preview_length - 3]}..."'

        return f' — "{clean}"'

    def cmd_add(self, args, **_):
        user = (args or "").strip()

        if not user:
            return

        with self._lock:
            self._whitelist_set.add(user)

        self._update_and_save()
        self.log(f"Added '{user}' to whitelist.")

    def cmd_remove(self, args, **_):
        user = (args or "").strip()

        if not user:
            return

        removed = False

        with self._lock:
            if user in self._whitelist_set:
                self._whitelist_set.remove(user)
                removed = True

        if removed:
            self._update_and_save()
            self.log(f"Removed '{user}'.")
        else:
            self.log(f"User '{user}' not in whitelist.")

    def cmd_list(self, *_args, **_kwargs):
        with self._lock:
            users_sorted = sorted(self._whitelist_set)

        users = ", ".join(users_sorted) or "Empty"
        self.log(f"Whitelist ({len(users_sorted)}): {users}")

    def cmd_import(self, *_args, **_kwargs):
        if not self.backup_file.exists():
            self.log(f"Import failed: Backup file not found at {self.backup_file}")
            return

        try:
            text = self.backup_file.read_text(encoding="utf-8", errors="replace")
        except PermissionError as e:
            self._log_error("Import failed (permission denied)", e)
            return
        except OSError as e:
            self._log_error("Import failed (OS error)", e)
            return

        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            self._log_error("Import failed (corrupt JSON)", e)
            return

        new_users = data.get("whitelist", [])

        if not isinstance(new_users, list):
            self.log("Import failed: JSON 'whitelist' is not a list.")
            return

        with self._lock:
            before = len(self._whitelist_set)

            for user in new_users:
                if isinstance(user, str):
                    user = user.strip()

                    if user:
                        self._whitelist_set.add(user)

            added = len(self._whitelist_set) - before

        self._update_and_save()
        self.log(f"Imported {added} users from JSON backup.")