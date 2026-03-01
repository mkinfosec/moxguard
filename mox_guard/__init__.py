# MoxGuard — Nicotine+ moderation plugin
# Handles trolls, racists, spammers, and general chat-ruiners.
#
# Detection layers:
#   1. Bad phrase / keyword matching (configurable list)
#   2. Flood detection (too many messages in a rolling window)
#   3. ASCII / character spam (same char repeated)
#   4. ALL CAPS shouting
#   5. Multi-nick detection (same IP, different username)
#
# Actions:
#   - Zap (silently drop) offending messages
#   - Log every violation with IP + country
#   - Auto-ignore users after reaching the warn threshold
#   - Taint IPs of ignored users → auto-ignore any new nick from that IP
#   - Whitelist trusted users to never filter

import os
import re
import time
from collections import defaultdict

from pynicotine.pluginsystem import BasePlugin
from pynicotine.pluginsystem import returncode


# ---------------------------------------------------------------------------
# Default bad-phrase list. Add/remove via the Nicotine+ plugin settings UI.
# ---------------------------------------------------------------------------
DEFAULT_BAD_PHRASES = [
    "nigger", "nigga", "n1gger",
    "chink", "ch1nk",
    "spic", "sp1c",
    "kike", "k1ke",
    "wetback", "raghead", "sandnigger", "paki",
    "tranny", "faggot", "f4ggot", "fag", "dyke",
    "kill yourself", "kys",
    "go back to",
    "white power", "white pride", "heil hitler",
    "14 words", "race traitor", "gas the",
    "oven dodger", "cotton picker",
    "subhuman", "mudblood", "mudshark",
    "child porn", "cp link", "jailbait",
]


class Plugin(BasePlugin):

    settings = {
        "bad_phrases":       DEFAULT_BAD_PHRASES,
        "whitelist":         [],
        "auto_ignore":       True,
        "warn_threshold":    1,
        "flood_limit":       8,
        "flood_window":      20,
        "caps_min_length":   12,
        "caps_ratio":        0.80,
        "char_repeat_min":   8,
        "log_to_file":       True,
        "log_path":          os.path.expanduser("~/.local/share/nicotine/moxguard.log"),
        "show_ip_in_log":    True,
        "multi_nick_detect": True,
    }

    metasettings = {
        "bad_phrases": {
            "description": "Phrases/words to block (case-insensitive)",
            "type": "list string"
        },
        "whitelist": {
            "description": "Users who are never filtered",
            "type": "list string"
        },
        "auto_ignore": {
            "description": "Automatically ignore users who exceed warn threshold",
            "type": "bool"
        },
        "warn_threshold": {
            "description": "Violations before auto-ignore kicks in",
            "type": "integer"
        },
        "flood_limit": {
            "description": "Max messages in flood window before flagging",
            "type": "integer"
        },
        "flood_window": {
            "description": "Flood detection window in seconds",
            "type": "integer"
        },
        "caps_min_length": {
            "description": "Minimum message length before ALL CAPS check applies",
            "type": "integer"
        },
        "caps_ratio": {
            "description": "Fraction of uppercase letters to trigger caps detection (0.0-1.0)",
            "type": "float"
        },
        "char_repeat_min": {
            "description": "Consecutive identical characters to flag as spam",
            "type": "integer"
        },
        "log_to_file": {
            "description": "Write violations to log file",
            "type": "bool"
        },
        "log_path": {
            "description": "Path to the MoxGuard log file",
            "type": "string"
        },
        "show_ip_in_log": {
            "description": "Show IP address and country in violation log",
            "type": "bool"
        },
        "multi_nick_detect": {
            "description": "Auto-ignore users who rejoin under a new nick from a tainted IP",
            "type": "bool"
        },
    }

    commands = {
        "moxguard": {
            "aliases":     ["mg"],
            "callback":    None,
            "description": "MoxGuard: status | ignore <u> | unignore <u> | whitelist <u> | unwhitelist <u> | clear <u> | ipinfo <u> | altnicks <u> | reload",
            "parameters":  ["<cmd>", "[user]"],
            "group":       "MoxGuard",
        }
    }

    # -----------------------------------------------------------------------

    def init(self):
        # Violation counts per user
        self._violations = defaultdict(int)

        # Message timestamps for flood detection
        self._msg_times = defaultdict(list)

        # IP tracking
        # user → ip
        self._user_to_ip = {}
        # ip → set of all usernames seen from it
        self._ip_to_users = defaultdict(set)
        # IPs associated with at least one ignored/bad user
        self._tainted_ips = set()
        # Users whose IP we've already requested (avoid duplicate requests)
        self._ip_requested = set()

        self._compile_patterns()
        self.commands["moxguard"]["callback"] = self._moxguard_command

        self.log(
            "MoxGuard loaded — %d phrases | flood %d/%ds | auto-ignore: %s | multi-nick: %s",
            (len(self.settings["bad_phrases"]),
             self.settings["flood_limit"],
             self.settings["flood_window"],
             self.settings["auto_ignore"],
             self.settings["multi_nick_detect"])
        )

    def _compile_patterns(self):
        escaped = [re.escape(p.lower()) for p in self.settings["bad_phrases"] if p.strip()]
        self._bad_re = re.compile(r"|".join(escaped)) if escaped else None

    # -----------------------------------------------------------------------
    # IP helpers
    # -----------------------------------------------------------------------

    def _request_ip(self, user):
        """Ask Nicotine+ to resolve a user's IP (async; arrives via user_resolve_notification)."""
        if user not in self._ip_requested:
            self._ip_requested.add(user)
            try:
                self.core.users.request_ip_address(user)
            except Exception:
                pass

    def _get_ip_info(self, user):
        """Return (ip, country) for a user from the local cache, or (None, None)."""
        addr = self.core.users.addresses.get(user)
        if addr:
            ip = addr[0]
            country = self.core.users.countries.get(user, "??")
            return ip, country
        return None, None

    def _fmt_ip(self, user):
        """Human-readable IP + country string, or empty string if unknown."""
        if not self.settings["show_ip_in_log"]:
            return ""
        ip, country = self._get_ip_info(user)
        if ip:
            return f" [{ip} | {country}]"
        return " [IP unknown]"

    def _taint_user_ip(self, user):
        """Mark the IP of an ignored user as tainted for multi-nick detection."""
        ip, _ = self._get_ip_info(user)
        if ip and ip not in ("0.0.0.0", ""):
            self._tainted_ips.add(ip)
            self._write_log(f"[IP-TAINT] {user} → {ip} added to tainted list")

    # -----------------------------------------------------------------------
    # Core violation handler
    # -----------------------------------------------------------------------

    def _violation(self, user, room, reason, message):
        self._violations[user] += 1
        count = self._violations[user]
        location = f"room:{room}" if room else "private"
        ip_str = self._fmt_ip(user)

        entry = (f"[VIOLATION #{count}] user={user}{ip_str} "
                 f"location={location} reason={reason} msg={message!r}")
        self.log(entry)
        self._write_log(entry)

        # Request IP if we don't have it yet (will process in user_resolve_notification)
        self._request_ip(user)

        if self.settings["auto_ignore"] and count >= self.settings["warn_threshold"]:
            self._do_ignore(user, reason=reason)

        return returncode["zap"]

    def _do_ignore(self, user, reason="manual"):
        """Ignore a user and taint their IP."""
        if self.core.network_filter.is_user_ignored(user):
            return
        self.core.network_filter.ignore_user(user)
        self._taint_user_ip(user)
        msg = f"[IGNORED] {user}{self._fmt_ip(user)} — reason: {reason}"
        self.log(msg)
        self._write_log(msg)

    def _write_log(self, line):
        if not self.settings["log_to_file"]:
            return
        try:
            with open(self.settings["log_path"], "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {line}\n")
        except OSError as e:
            self.log("Log write failed: %s", (e,))

    # -----------------------------------------------------------------------
    # Detection layers
    # -----------------------------------------------------------------------

    def _check_message(self, user, line, room=None):
        if self._is_whitelisted(user):
            return None

        # Already ignored — zap and make sure IP is tainted
        if self.core.network_filter.is_user_ignored(user):
            self._taint_user_ip(user)
            return returncode["zap"]

        # 1. Bad phrase
        if self._bad_re and self._bad_re.search(line.lower()):
            matched = self._bad_re.search(line.lower()).group(0)
            return self._violation(user, room, f"bad_phrase:{matched!r}", line)

        # 2. Flood
        now   = time.monotonic()
        limit = self.settings["flood_limit"]
        win   = self.settings["flood_window"]
        times = self._msg_times[user]
        times[:] = [t for t in times if now - t < win]
        times.append(now)
        if len(times) > limit:
            return self._violation(user, room, f"flood:{len(times)}_in_{win}s", line)

        # 3. Char-repeat spam
        repeat_min = self.settings["char_repeat_min"]
        if re.search(r"(.)\1{" + str(repeat_min - 1) + r",}", line):
            return self._violation(user, room, "char_spam", line)

        # 4. ALL CAPS
        min_len    = self.settings["caps_min_length"]
        caps_ratio = self.settings["caps_ratio"]
        alphas     = [c for c in line if c.isalpha()]
        if (len(line) >= min_len
                and len(alphas) >= 4
                and sum(c.isupper() for c in alphas) / len(alphas) >= caps_ratio):
            return self._violation(user, room, "all_caps", line)

        # Ensure we're collecting IPs on all active chatters
        self._request_ip(user)
        return None

    def _is_whitelisted(self, user):
        return user.lower() in [w.lower() for w in self.settings["whitelist"]]

    # -----------------------------------------------------------------------
    # Nicotine+ event hooks
    # -----------------------------------------------------------------------

    def incoming_public_chat_event(self, room, user, line):
        result = self._check_message(user, line, room=room)
        if result is not None:
            return result
        return None

    def incoming_private_chat_event(self, user, line):
        result = self._check_message(user, line, room=None)
        if result is not None:
            return result
        return None

    def user_join_chatroom_notification(self, room, user):
        """Proactively request IP for everyone who joins a room we're in."""
        self._request_ip(user)

    def user_resolve_notification(self, user, ip_address, port, country):
        """
        Fired when Nicotine+ resolves a user's IP address.
        We use this to:
          1. Update our IP ↔ username maps
          2. Detect multi-nick (new username, tainted IP)
        """
        if not ip_address or ip_address == "0.0.0.0":
            return

        # Update maps
        self._user_to_ip[user] = ip_address
        self._ip_to_users[ip_address].add(user)

        # Log IP info for anyone with existing violations
        if user in self._violations and self.settings["show_ip_in_log"]:
            country_str = country or "??"
            altnicks = self._ip_to_users[ip_address] - {user}
            alt_str  = f" | altnicks: {', '.join(sorted(altnicks))}" if altnicks else ""
            self.log(
                "[IP-RESOLVED] %s → %s (%s)%s violations=%d",
                (user, ip_address, country_str, alt_str, self._violations[user])
            )

        # Multi-nick detection
        if not self.settings["multi_nick_detect"]:
            return
        if self._is_whitelisted(user):
            return
        if self.core.network_filter.is_user_ignored(user):
            # Already handled — just make sure the IP is tainted
            self._tainted_ips.add(ip_address)
            return

        if ip_address in self._tainted_ips:
            # This is a new (or returning) nick from a known-bad IP
            known_bad = [u for u in self._ip_to_users[ip_address]
                         if self.core.network_filter.is_user_ignored(u)]
            reason = f"multi_nick|ip:{ip_address}|same_as:{','.join(known_bad)}"
            country_str = country or "??"

            entry = (f"[MULTI-NICK] {user} [{ip_address} | {country_str}] "
                     f"matches tainted IP — known bad nicks: {known_bad}")
            self.log(entry)
            self._write_log(entry)

            self._violations[user] += 1
            if self.settings["auto_ignore"]:
                self._do_ignore(user, reason=reason)

    # -----------------------------------------------------------------------
    # Commands
    # -----------------------------------------------------------------------

    def _moxguard_command(self, args, room=None, user=None):
        parts = args.strip().split(None, 1)
        cmd   = parts[0].lower() if parts else ""
        arg   = parts[1].strip() if len(parts) > 1 else ""

        dispatch = {
            "status":      lambda: self._cmd_status(),
            "ignore":      lambda: self._cmd_ignore(arg) if arg else self.output("Usage: /mg ignore <user>"),
            "unignore":    lambda: self._cmd_unignore(arg) if arg else self.output("Usage: /mg unignore <user>"),
            "whitelist":   lambda: self._cmd_whitelist(arg) if arg else self.output("Usage: /mg whitelist <user>"),
            "unwhitelist": lambda: self._cmd_unwhitelist(arg) if arg else self.output("Usage: /mg unwhitelist <user>"),
            "clear":       lambda: self._cmd_clear(arg) if arg else self.output("Usage: /mg clear <user>"),
            "ipinfo":      lambda: self._cmd_ipinfo(arg) if arg else self.output("Usage: /mg ipinfo <user>"),
            "altnicks":    lambda: self._cmd_altnicks(arg) if arg else self.output("Usage: /mg altnicks <user>"),
            "reload":      lambda: self._cmd_reload(),
        }

        fn = dispatch.get(cmd)
        if fn:
            fn()
        else:
            self.output(
                "MoxGuard commands:\n"
                "  /mg status\n"
                "  /mg ignore <user>       — manually ignore\n"
                "  /mg unignore <user>\n"
                "  /mg whitelist <user>    — never filter this user\n"
                "  /mg unwhitelist <user>\n"
                "  /mg clear <user>        — reset violation count\n"
                "  /mg ipinfo <user>       — show IP + country + altnicks\n"
                "  /mg altnicks <user>     — list all nicks seen from same IP\n"
                "  /mg reload              — recompile phrase list\n"
            )

    def _cmd_status(self):
        ignored_count = sum(
            1 for u in self._violations
            if self.core.network_filter.is_user_ignored(u)
        )
        lines = [
            "=== MoxGuard Status ===",
            f"  Phrases     : {len(self.settings['bad_phrases'])}",
            f"  Auto-ignore : {self.settings['auto_ignore']} (after {self.settings['warn_threshold']} violation(s))",
            f"  Flood limit : {self.settings['flood_limit']} msgs / {self.settings['flood_window']}s",
            f"  Multi-nick  : {self.settings['multi_nick_detect']}",
            f"  Tainted IPs : {len(self._tainted_ips)}",
            f"  Whitelist   : {self.settings['whitelist'] or '(empty)'}",
            f"  Users flagged: {len(self._violations)} | auto-ignored: {ignored_count}",
        ]
        if self._violations:
            lines.append("  Top offenders:")
            for u, c in sorted(self._violations.items(), key=lambda x: -x[1])[:10]:
                ip, country = self._get_ip_info(u)
                ip_str     = f" [{ip} | {country}]" if ip else ""
                status     = " [IGNORED]" if self.core.network_filter.is_user_ignored(u) else ""
                altnicks   = self._get_altnicks(u)
                alt_str    = f" altnicks:{altnicks}" if altnicks else ""
                lines.append(f"    {u}{ip_str}{status} — {c} violation(s){alt_str}")
        self.output("\n".join(lines))

    def _cmd_ipinfo(self, user):
        ip, country = self._get_ip_info(user)
        if not ip:
            self._request_ip(user)
            self.output(f"No cached IP for {user} — requesting... check again in a moment.")
            return
        tainted = "YES (tainted)" if ip in self._tainted_ips else "no"
        altnicks = self._get_altnicks(user)
        lines = [
            f"=== IP Info: {user} ===",
            f"  IP      : {ip}",
            f"  Country : {country or '??'}",
            f"  Tainted : {tainted}",
            f"  Altnicks: {', '.join(altnicks) if altnicks else '(none seen)'}",
            f"  Violations: {self._violations.get(user, 0)}",
            f"  Ignored : {self.core.network_filter.is_user_ignored(user)}",
        ]
        self.output("\n".join(lines))

    def _cmd_altnicks(self, user):
        ip, country = self._get_ip_info(user)
        if not ip:
            self.output(f"No cached IP for {user} — try /mg ipinfo {user} first.")
            return
        altnicks = self._get_altnicks(user)
        if not altnicks:
            self.output(f"No other nicks seen from {user}'s IP ({ip}).")
            return
        lines = [f"=== Altnicks for {user} [{ip} | {country or '??'}] ==="]
        for nick in sorted(altnicks):
            status = " [IGNORED]" if self.core.network_filter.is_user_ignored(nick) else ""
            v = self._violations.get(nick, 0)
            lines.append(f"  {nick}{status} — {v} violation(s)")
        self.output("\n".join(lines))

    def _get_altnicks(self, user):
        ip = self._user_to_ip.get(user)
        if not ip:
            return []
        return sorted(self._ip_to_users[ip] - {user})

    def _cmd_ignore(self, user):
        if self.core.network_filter.is_user_ignored(user):
            self.output(f"{user} is already ignored.")
            return
        self._do_ignore(user, reason="manual")
        self.output(f"Ignored {user}.")

    def _cmd_unignore(self, user):
        if not self.core.network_filter.is_user_ignored(user):
            self.output(f"{user} is not ignored.")
            return
        self.core.network_filter.unignore_user(user)
        self.output(f"Unignored {user}.")
        self._write_log(f"[MANUAL] Unignored {user}")

    def _cmd_whitelist(self, user):
        wl = self.settings["whitelist"]
        if user.lower() in [w.lower() for w in wl]:
            self.output(f"{user} is already whitelisted.")
            return
        wl.append(user)
        self.output(f"Added {user} to whitelist.")
        self._write_log(f"[MANUAL] Whitelisted {user}")

    def _cmd_unwhitelist(self, user):
        wl    = self.settings["whitelist"]
        match = next((w for w in wl if w.lower() == user.lower()), None)
        if not match:
            self.output(f"{user} is not whitelisted.")
            return
        wl.remove(match)
        self.output(f"Removed {user} from whitelist.")
        self._write_log(f"[MANUAL] Removed {user} from whitelist")

    def _cmd_reload(self):
        self._compile_patterns()
        self.output(f"Phrase list recompiled — {len(self.settings['bad_phrases'])} patterns active.")

    def _cmd_clear(self, user):
        self._violations.pop(user, None)
        self._msg_times.pop(user, None)
        self.output(f"Cleared violation history for {user}.")
        self._write_log(f"[MANUAL] Cleared violation count for {user}")
