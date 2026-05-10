WhiteList is a Nicotine+ plugin that filters chat messages based on a configurable username whitelist.

Users not present in the whitelist can be blocked from:

- Public chatrooms
- Private messages (optional)

The plugin also supports:

- Preview logging of blocked messages
- Periodic JSON backups
- JSON import/restore
- Runtime-safe settings sanitization

Commands:

  /wla <user>
Add a user to the whitelist.

  /wlr <user>
Remove a user from the whitelist.

  /wll
List all whitelisted users.

  /wli
Import whitelist users from JSON backup.


Whitelist entries are normalized and deduplicated automatically
Preview logs are rate-limited per user to prevent spam
Backup timers restart automatically after settings changes
Invalid or corrupted JSON backups are handled safely
