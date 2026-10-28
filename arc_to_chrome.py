#!/usr/bin/env python3
"""arc-to-chrome — merge Arc browser data (logins, history, cookies, spaces) into Chrome on macOS.

Both browsers are Chromium: same SQLite schemas, same "v10" AES-128-CBC encryption,
different Keychain keys ("Arc Safe Storage" vs "Chrome Safe Storage").
This tool decrypts with Arc's key, re-encrypts with Chrome's key, and merges —
fully offline, and decrypted secrets never touch disk.

Commands:
    profiles  list Arc & Chrome profiles, Spaces, and auto-detected pairings
    spaces    list, export to HTML, or merge Arc Spaces into Chrome Bookmarks
    diff      preview what logins/history/cookies would be merged (read-only)
    merge     perform logins/history/cookies merge (Chrome must be quit)
    selftest  crypto sanity checks (round-trip, padding tamper, wrong-key)
"""
import argparse
import hashlib
import html
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import closing

from Crypto.Cipher import AES

ARC_BASE_DIR = os.path.expanduser("~/Library/Application Support/Arc/User Data")
CHROME_BASE_DIR = os.path.expanduser("~/Library/Application Support/Google/Chrome")
ARC_SIDEBAR_PATH = os.path.expanduser("~/Library/Application Support/Arc/StorableSidebar.json")
BACKUP_ROOT = os.path.expanduser("~/arc-to-chrome-backups")
CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01

ARC_KEYCHAIN = "Arc Safe Storage"
CHROME_KEYCHAIN = "Chrome Safe Storage"

NAME_RE = re.compile(r"^[a-z_]+$")  # whitelist for table/column names in dynamic SQL
COOKIE_KEY_COLS = ("host_key", "top_frame_site_key", "has_cross_site_ancestor", "name",
                   "path", "source_scheme", "source_port")
DB_FILES = ("Login Data", "History", "Cookies")


class ToolError(Exception):
    pass


# ---------------------------------------------------------------- crypto

def get_key(service):
    """Read a Chromium Safe Storage secret from Keychain, derive the AES-128 key."""
    try:
        pw = subprocess.run(["security", "find-generic-password", "-s", service, "-w"],
                            capture_output=True, text=True, check=True).stdout.rstrip("\n")
    except subprocess.CalledProcessError:
        raise ToolError(f"cannot read Keychain item '{service}' — "
                        "please click Allow in the macOS prompt")
    return hashlib.pbkdf2_hmac("sha1", pw.encode(), b"saltysalt", 1003, 16)


def v10_decrypt(key, blob):
    """Decrypt a Chromium v10 blob with strict PKCS#7 validation.

    Returns plaintext bytes, or None for non-v10 input, malformed length,
    or padding that fails validation (the common case for a wrong key).
    A wrong key therefore lands in the caller's failure count instead of
    silently producing garbage plaintext.
    """
    if not blob or blob[:3] != b"v10":
        return None
    ct = blob[3:]
    if not ct or len(ct) % 16:
        return None
    pt = AES.new(key, AES.MODE_CBC, iv=b" " * 16).decrypt(ct)
    pad = pt[-1]
    if not 1 <= pad <= 16 or pt[-pad:] != bytes([pad]) * pad:
        return None
    return pt[:-pad]


def v10_encrypt(key, pt):
    pad = 16 - (len(pt) % 16)
    pt = pt + bytes([pad]) * pad
    return b"v10" + AES.new(key, AES.MODE_CBC, iv=b" " * 16).encrypt(pt)


# ---------------------------------------------------------------- db helpers

def chrome_running():
    return subprocess.run(["pgrep", "-x", "Google Chrome"],
                          capture_output=True).returncode == 0


def backup_db(src_path, dst_path, attempts=3):
    """Snapshot a browser SQLite DB. Returns "consistent" or "best-effort"."""
    for _ in range(attempts):
        if os.path.exists(dst_path):
            os.unlink(dst_path)
        mode = "consistent"
        try:
            with closing(sqlite3.connect(f"file:{src_path}?mode=ro", uri=True,
                                         timeout=2)) as src:
                src.execute("VACUUM INTO ?", (dst_path,))
        except sqlite3.OperationalError:
            mode = "best-effort"
            if os.path.exists(dst_path):
                os.unlink(dst_path)
            with closing(sqlite3.connect(f"file:{src_path}?mode=ro&immutable=1",
                                         uri=True)) as src:
                src.execute("VACUUM INTO ?", (dst_path,))
        with closing(sqlite3.connect(dst_path)) as chk:
            ok = chk.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        if ok:
            os.chmod(dst_path, 0o600)
            return mode
    raise ToolError(f"could not snapshot {src_path} (database busy) — try again")


def check_name(kind, name):
    if not NAME_RE.match(name):
        raise ToolError(f"unexpected {kind} name: {name!r}")


def table_columns(conn, table):
    check_name("table", table)
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    for c in cols:
        check_name("column", c)
    return cols


def insert_row(conn, table, row, cols):
    check_name("table", table)
    conn.execute(f"INSERT INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                 [row.get(c) for c in cols])


def require_profile_files(arc_dir, chrome_dir, what=DB_FILES):
    for base, label in ((arc_dir, "Arc"), (chrome_dir, "Chrome")):
        for name in what:
            p = os.path.join(base, name)
            if not os.path.exists(p):
                raise ToolError(f"{label} profile file not found: {p} "
                                f"(is {label} profile '{os.path.basename(base)}' properly initialized?)")


def backup_chrome_profile(chrome_dir, what=DB_FILES):
    dest = os.path.join(BACKUP_ROOT, f"{time.strftime('%Y%m%d-%H%M%S')}_{os.path.basename(chrome_dir)}")
    os.makedirs(dest, mode=0o700, exist_ok=True)
    os.chmod(dest, 0o700)
    for name in what:
        src = os.path.join(chrome_dir, name)
        if os.path.exists(src):
            backup_db(src, os.path.join(dest, name))
    return dest


def cookie_key(d):
    return tuple(d[c] for c in COOKIE_KEY_COLS)


# ---------------------------------------------------------------- profile discovery

def load_arc_profiles():
    """Returns a dict of {dir_name: {'dir': dir_name, 'name': display_name, 'spaces': [space_names], 'favorites_count': int}}"""
    ls_path = os.path.join(ARC_BASE_DIR, "Local State")
    profiles = {}
    if os.path.exists(ls_path):
        try:
            with open(ls_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in data.get("profile", {}).get("info_cache", {}).items():
                profiles[k] = {"dir": k, "name": v.get("name", k), "spaces": [], "favorites_count": 0}
        except Exception:
            pass
    if os.path.exists(ARC_BASE_DIR):
        for entry in os.listdir(ARC_BASE_DIR):
            if (entry == "Default" or entry.startswith("Profile ")) and os.path.isdir(os.path.join(ARC_BASE_DIR, entry)):
                if entry not in profiles:
                    profiles[entry] = {"dir": entry, "name": entry, "spaces": [], "favorites_count": 0}

    # Cross-reference with StorableSidebar.json
    if os.path.exists(ARC_SIDEBAR_PATH):
        try:
            with open(ARC_SIDEBAR_PATH, "r", encoding="utf-8") as f:
                sb_data = json.load(f)
            c1 = sb_data.get("sidebar", {}).get("containers", [{}, {}])[1]
            spaces_raw = [s for s in c1.get("spaces", []) if isinstance(s, dict)]
            for s in spaces_raw:
                s_title = s.get("title", "")
                prof = s.get("profile", {})
                prof_dir = "Default" if prof.get("default") else prof.get("custom", {}).get("_0", {}).get("directoryBasename", "Default")
                if prof_dir in profiles:
                    if s_title and s_title not in profiles[prof_dir]["spaces"]:
                        profiles[prof_dir]["spaces"].append(s_title)
                else:
                    profiles[prof_dir] = {"dir": prof_dir, "name": prof_dir, "spaces": [s_title], "favorites_count": 0}

            top_apps = c1.get("topAppsContainerIDs", [])
            items_dict = {it["id"]: it for it in c1.get("items", []) if isinstance(it, dict)}
            for i in range(0, len(top_apps), 2):
                p_info = top_apps[i]
                cid = top_apps[i+1]
                p_dir = "Default" if p_info.get("default") else p_info.get("custom", {}).get("_0", {}).get("directoryBasename", "Default")
                c_item = items_dict.get(cid)
                if c_item and p_dir in profiles:
                    profiles[p_dir]["favorites_count"] = len(c_item.get("childrenIds", []))
        except Exception:
            pass

    return profiles


def load_chrome_profiles():
    """Returns a dict of {dir_name: {'dir': dir_name, 'name': display_name, 'user_name': email}}"""
    ls_path = os.path.join(CHROME_BASE_DIR, "Local State")
    profiles = {}
    if os.path.exists(ls_path):
        try:
            with open(ls_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in data.get("profile", {}).get("info_cache", {}).items():
                profiles[k] = {"dir": k, "name": v.get("name", k), "user_name": v.get("user_name", "")}
        except Exception:
            pass
    if os.path.exists(CHROME_BASE_DIR):
        for entry in os.listdir(CHROME_BASE_DIR):
            if (entry == "Default" or entry.startswith("Profile ")) and os.path.isdir(os.path.join(CHROME_BASE_DIR, entry)):
                if entry not in profiles:
                    profiles[entry] = {"dir": entry, "name": entry, "user_name": ""}
    return profiles


def resolve_profile(spec, browser_type="arc"):
    """Resolve user input (dir name, display name, or space name) to profile dict."""
    profs = load_arc_profiles() if browser_type == "arc" else load_chrome_profiles()
    if not spec:
        spec = "Default"
    # 1. Exact dir match
    if spec in profs:
        return profs[spec]
    # 2. Display name match (case-insensitive)
    for p in profs.values():
        if p["name"].lower() == spec.lower():
            return p
    # 3. For Arc, check associated space name
    if browser_type == "arc":
        for p in profs.values():
            if any(s.lower() == spec.lower() for s in p.get("spaces", [])):
                return p
    # 4. Partial number match (e.g. "1" -> "Profile 1")
    if spec.isdigit():
        target = f"Profile {spec}"
        if target in profs:
            return profs[target]
    raise ToolError(f"unknown {browser_type.title()} profile '{spec}'. "
                    f"Available profiles: {', '.join(sorted(profs.keys()))}")


def get_profile_matches():
    """Return list of (arc_profile, chrome_profile) pairs matched by display name or Default."""
    arc_profs = load_arc_profiles()
    chr_profs = load_chrome_profiles()
    matches = []
    for a_dir, a_info in arc_profs.items():
        # Match by name
        c_match = next((c for c in chr_profs.values() if c["name"].lower() == a_info["name"].lower()), None)
        if c_match:
            matches.append((a_info, c_match))
        elif a_dir == "Default" and "Default" in chr_profs:
            matches.append((a_info, chr_profs["Default"]))
    return matches


# ---------------------------------------------------------------- spaces & bookmarks

def parse_arc_sidebar():
    """Parse StorableSidebar.json into structured spaces and profile favorites."""
    if not os.path.exists(ARC_SIDEBAR_PATH):
        raise ToolError(f"Arc sidebar data not found at {ARC_SIDEBAR_PATH}")
    with open(ARC_SIDEBAR_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    try:
        c1 = data["sidebar"]["containers"][1]
    except (KeyError, IndexError):
        raise ToolError("Invalid StorableSidebar.json structure")

    items_dict = {it["id"]: it for it in c1.get("items", []) if isinstance(it, dict)}
    spaces_raw = [s for s in c1.get("spaces", []) if isinstance(s, dict)]
    arc_profs = load_arc_profiles()

    def parse_node(item_id):
        item = items_dict.get(item_id)
        if not item:
            return None
        data_field = item.get("data", {})
        if not isinstance(data_field, dict):
            return None
        if "tab" in data_field:
            tab = data_field["tab"]
            url = tab.get("savedURL") or ""
            title = tab.get("savedTitle") or item.get("title") or url
            return {"type": "url", "title": title, "url": url}
        elif "list" in data_field:
            title = item.get("title") or "Folder"
            children = []
            for cid in item.get("childrenIds", []):
                ch = parse_node(cid)
                if ch:
                    if ch["type"] == "split":
                        children.extend(ch["children"])
                    else:
                        children.append(ch)
            return {"type": "folder", "title": title, "children": children}
        elif "splitView" in data_field:
            children = []
            for cid in item.get("childrenIds", []):
                ch = parse_node(cid)
                if ch:
                    if ch["type"] == "split":
                        children.extend(ch["children"])
                    else:
                        children.append(ch)
            return {"type": "split", "children": children}
        return None

    # Parse spaces
    spaces = []
    for s in spaces_raw:
        title = s.get("title", "Untitled")
        s_id = s.get("id")
        prof = s.get("profile", {})
        p_dir = "Default" if prof.get("default") else prof.get("custom", {}).get("_0", {}).get("directoryBasename", "Default")
        p_name = arc_profs.get(p_dir, {}).get("name", p_dir)

        cids = s.get("containerIDs", [])
        containers = {}
        for i in range(0, len(cids), 2):
            if i + 1 < len(cids) and isinstance(cids[i], str):
                containers[cids[i]] = cids[i+1]

        pinned_cid = containers.get("pinned")
        unpinned_cid = containers.get("unpinned")

        pinned = []
        if pinned_cid and pinned_cid in items_dict:
            for cid in items_dict[pinned_cid].get("childrenIds", []):
                node = parse_node(cid)
                if node:
                    if node["type"] == "split":
                        pinned.extend(node["children"])
                    else:
                        pinned.append(node)

        unpinned = []
        if unpinned_cid and unpinned_cid in items_dict:
            for cid in items_dict[unpinned_cid].get("childrenIds", []):
                node = parse_node(cid)
                if node:
                    if node["type"] == "split":
                        unpinned.extend(node["children"])
                    else:
                        unpinned.append(node)

        spaces.append({
            "id": s_id,
            "title": title,
            "profile_dir": p_dir,
            "profile_name": p_name,
            "pinned": pinned,
            "unpinned": unpinned
        })

    # Parse favorites per profile
    top_apps = c1.get("topAppsContainerIDs", [])
    favorites = {}
    for i in range(0, len(top_apps), 2):
        p_info = top_apps[i]
        cid = top_apps[i+1]
        p_dir = "Default" if p_info.get("default") else p_info.get("custom", {}).get("_0", {}).get("directoryBasename", "Default")
        c_item = items_dict.get(cid)
        fav_list = []
        for ch_id in (c_item.get("childrenIds", []) if c_item else []):
            node = parse_node(ch_id)
            if node:
                if node["type"] == "split":
                    fav_list.extend(node["children"])
                else:
                    fav_list.append(node)
        if fav_list:
            favorites[p_dir] = fav_list

    return {"spaces": spaces, "favorites": favorites}


def count_tree_nodes(items):
    urls = 0
    folders = 0
    for it in items:
        if it["type"] == "url":
            urls += 1
        elif it["type"] == "folder":
            folders += 1
            u, f = count_tree_nodes(it.get("children", []))
            urls += u
            folders += f
    return urls, folders


def generate_html_bookmarks(tree):
    """Generate standard Netscape Bookmarks HTML file."""
    lines = [
        "<!DOCTYPE NETSCAPE-Bookmark-file-1>",
        "<!-- This is an automatically generated file.",
        "     It will be read and overwritten.",
        "     DO NOT EDIT! -->",
        '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">',
        "<TITLE>Bookmarks</TITLE>",
        "<H1>Bookmarks</H1>",
        "<DL><p>"
    ]
    now = int(time.time())

    def dump_node(node, indent):
        sp = "    " * indent
        if node["type"] == "url":
            title = html.escape(node.get("title") or node.get("url") or "")
            url = html.escape(node.get("url") or "")
            lines.append(f'{sp}<DT><A HREF="{url}" ADD_DATE="{now}">{title}</A>')
        elif node["type"] == "folder":
            title = html.escape(node.get("title") or "Folder")
            lines.append(f'{sp}<DT><H3 ADD_DATE="{now}" LAST_MODIFIED="{now}">{title}</H3>')
            lines.append(f"{sp}<DL><p>")
            for child in node.get("children", []):
                dump_node(child, indent + 1)
            lines.append(f"{sp}</DL><p>")

    for root in tree:
        dump_node(root, 1)
    lines.append("</DL><p>")
    return "\n".join(lines) + "\n"


def merge_chrome_bookmarks(chrome_dir, folders_to_add, dry_run=False):
    """Merge folder trees into Chrome's bookmark file (AccountBookmarks or Bookmarks)."""
    acc_bm_path = os.path.join(chrome_dir, "AccountBookmarks")
    bm_path = os.path.join(chrome_dir, "Bookmarks")
    target_path = acc_bm_path if os.path.exists(acc_bm_path) else bm_path

    if os.path.exists(target_path):
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        now_us = str(int((time.time() + CHROME_EPOCH_OFFSET) * 1e6))
        data = {
            "checksum": "",
            "roots": {
                "bookmark_bar": {
                    "children": [],
                    "date_added": now_us,
                    "date_last_used": "0",
                    "date_modified": now_us,
                    "id": "1",
                    "name": "Bookmarks bar",
                    "type": "folder"
                },
                "other": {
                    "children": [],
                    "date_added": now_us,
                    "date_last_used": "0",
                    "date_modified": "0",
                    "id": "2",
                    "name": "Other bookmarks",
                    "type": "folder"
                },
                "synced": {
                    "children": [],
                    "date_added": now_us,
                    "date_last_used": "0",
                    "date_modified": "0",
                    "id": "3",
                    "name": "Mobile bookmarks",
                    "type": "folder"
                }
            },
            "version": 1
        }

    def find_max_id(node):
        max_id = 0
        if isinstance(node, dict):
            if "id" in node:
                try:
                    max_id = max(max_id, int(node["id"]))
                except ValueError:
                    pass
            for v in node.values():
                if isinstance(v, (dict, list)):
                    max_id = max(max_id, find_max_id(v))
        elif isinstance(node, list):
            for it in node:
                max_id = max(max_id, find_max_id(it))
        return max_id

    curr_id = max(find_max_id(data), 3)

    def convert_node(item):
        nonlocal curr_id
        now_us = str(int((time.time() + CHROME_EPOCH_OFFSET) * 1e6))
        if item["type"] == "url":
            curr_id += 1
            return {
                "date_added": now_us,
                "date_last_used": "0",
                "guid": str(uuid.uuid4()),
                "id": str(curr_id),
                "name": item.get("title") or item.get("url") or "",
                "type": "url",
                "url": item.get("url") or ""
            }
        elif item["type"] == "folder":
            curr_id += 1
            f_id = str(curr_id)
            children = [convert_node(ch) for ch in item.get("children", [])]
            return {
                "children": children,
                "date_added": now_us,
                "date_last_used": "0",
                "date_modified": now_us,
                "guid": str(uuid.uuid4()),
                "id": f_id,
                "name": item.get("title") or "Folder",
                "type": "folder"
            }

    new_folders = [convert_node(f) for f in folders_to_add]
    bar_children = data["roots"]["bookmark_bar"].setdefault("children", [])

    new_names = {f["name"] for f in new_folders}
    merged_children = [c for c in bar_children if c.get("name") not in new_names]
    merged_children.extend(new_folders)
    data["roots"]["bookmark_bar"]["children"] = merged_children

    if not dry_run:
        if os.path.exists(target_path):
            backup_dir = os.path.join(BACKUP_ROOT, f"{time.strftime('%Y%m%d-%H%M%S')}_{os.path.basename(chrome_dir)}")
            os.makedirs(backup_dir, mode=0o700, exist_ok=True)
            with open(os.path.join(backup_dir, os.path.basename(target_path)), "w", encoding="utf-8") as bf:
                with open(target_path, "r", encoding="utf-8") as src:
                    bf.write(src.read())

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=3, ensure_ascii=False)

    return target_path, len(new_folders)


# ---------------------------------------------------------------- plan layer

def plan_logins(arc_path, chrome_path, arc_key):
    with closing(sqlite3.connect(arc_path)) as arc, \
         closing(sqlite3.connect(chrome_path)) as main:
        cols, arc_cols = table_columns(main, "logins"), table_columns(arc, "logins")
        existing = set(main.execute("SELECT signon_realm, username_value FROM logins"))
        rows, skipped, failed = [], 0, 0
        for row in arc.execute("SELECT * FROM logins WHERE blacklisted_by_user = 0"):
            d = dict(zip(arc_cols, row))
            if (d["signon_realm"], d["username_value"]) in existing:
                skipped += 1
                continue
            pt = v10_decrypt(arc_key, d["password_value"])
            if not pt:
                failed += 1
                continue
            d = {k: v for k, v in d.items() if k in cols and k != "id"}
            d["_pt"] = pt
            rows.append(d)
        return {"rows": rows, "skipped": skipped, "failed": failed}


def iter_new_visits(arc_conn, arc_v_cols, urlmap, new_arc_ids, existing_visits, seen_new):
    """Single source of truth for visit dedupe rules (used by plan and apply)."""
    for row in arc_conn.execute("SELECT * FROM visits"):
        d = dict(zip(arc_v_cols, row))
        if d["url"] in urlmap:
            key = (urlmap[d["url"]], d["visit_time"])
            if key in existing_visits:
                continue
            existing_visits.add(key)
        elif d["url"] in new_arc_ids:
            key = (d["url"], d["visit_time"])
            if key in seen_new:
                continue
            seen_new.add(key)
        else:
            continue
        yield d


def plan_history(arc_path, chrome_path):
    with closing(sqlite3.connect(arc_path)) as arc, \
         closing(sqlite3.connect(chrome_path)) as main:
        url_cols = table_columns(main, "urls")
        if url_cols != table_columns(arc, "urls"):
            raise ToolError("urls schema mismatch between Arc and Chrome")
        arc_v_cols = table_columns(arc, "visits")
        existing_urls = {u: i for u, i in main.execute("SELECT url, id FROM urls")}
        urlmap, new_urls = {}, []
        arc_url_count = 0
        for row in arc.execute("SELECT * FROM urls"):
            d = dict(zip(url_cols, row))
            arc_url_count += 1
            if d["url"] in existing_urls:
                urlmap[d["id"]] = existing_urls[d["url"]]
            else:
                new_urls.append((d["id"], {k: v for k, v in d.items() if k != "id"}))
        new_arc_ids = {arc_id for arc_id, _ in new_urls}
        existing_visits = set(main.execute("SELECT url, visit_time FROM visits"))
        arc_visit_count = arc.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
        new_visits = sum(1 for _ in iter_new_visits(
            arc, arc_v_cols, urlmap, new_arc_ids, existing_visits, set()))
        return {"new_urls": new_urls, "urlmap": urlmap,
                "new_visits": new_visits, "arc_v_cols": arc_v_cols,
                "arc_url_count": arc_url_count, "arc_visit_count": arc_visit_count}


def plan_cookies(arc_path, chrome_path, arc_key):
    with closing(sqlite3.connect(arc_path)) as arc, \
         closing(sqlite3.connect(chrome_path)) as main:
        cols = table_columns(main, "cookies")
        arc_cols = table_columns(arc, "cookies")
        if cols != arc_cols:
            raise ToolError("cookies schema mismatch between Arc and Chrome")
        chr_map = {}
        for row in main.execute(f"SELECT {','.join(COOKIE_KEY_COLS)}, last_update_utc "
                                "FROM cookies"):
            chr_map[tuple(row[:-1])] = row[-1]
        now = int((time.time() + CHROME_EPOCH_OFFSET) * 1e6)
        insert, overwrite, kept, expired, failed = [], [], 0, 0, 0
        sel = ", ".join(f"CAST({c} AS BLOB)" if c == "encrypted_value" else c
                        for c in arc_cols)
        for row in arc.execute(f"SELECT {sel} FROM cookies"):
            d = dict(zip(arc_cols, row))
            if d["expires_utc"] and d["expires_utc"] < now:
                expired += 1
                continue
            pt = v10_decrypt(arc_key, d["encrypted_value"])
            if pt is None:
                failed += 1
                continue
            d["_pt"] = pt
            k = cookie_key(d)
            if k in chr_map:
                if d["last_update_utc"] <= chr_map[k]:
                    kept += 1
                    continue
                overwrite.append(d)
            else:
                insert.append(d)
        return {"insert": insert, "overwrite": overwrite, "kept": kept,
                "expired": expired, "failed": failed, "cols": cols}


# ---------------------------------------------------------------- apply layer

def apply_logins(plan, chrome_path, chr_key):
    inserted = 0
    with closing(sqlite3.connect(chrome_path)) as main:
        try:
            for d in plan["rows"]:
                pt = d["_pt"]
                row = {k: v for k, v in d.items() if k != "_pt"}
                row["password_value"] = v10_encrypt(chr_key, pt)
                insert_row(main, "logins", row, tuple(row))
                back = main.execute("SELECT password_value FROM logins "
                                    "WHERE id = last_insert_rowid()").fetchone()[0]
                if v10_decrypt(chr_key, back) != pt:
                    raise ToolError(
                        f"round-trip verify failed for {d['signon_realm']} — "
                        "logins rolled back, nothing was written")
                inserted += 1
        except Exception:
            main.rollback()
            raise
        main.commit()
        total = main.execute("SELECT COUNT(*) FROM logins").fetchone()[0]
    return (f"logins: +{inserted} new ({inserted}/{inserted} verify ok), "
            f"{plan['skipped']} already present, {plan['failed']} undecryptable/empty "
            f"| chrome total: {total}")


def apply_history(plan, arc_path, chrome_path):
    new_urls = new_visits = 0
    with closing(sqlite3.connect(arc_path)) as arc, \
         closing(sqlite3.connect(chrome_path)) as main:
        v_cols = table_columns(main, "visits")
        cur = main.cursor()
        urlmap = dict(plan["urlmap"])
        for arc_id, d in plan["new_urls"]:
            insert_row(cur, "urls", d, tuple(d))
            urlmap[arc_id] = cur.lastrowid
            new_urls += 1
        existing_visits = set(cur.execute("SELECT url, visit_time FROM visits"))
        touched = set()
        for d in iter_new_visits(arc, plan["arc_v_cols"], urlmap, set(),
                                 existing_visits, set()):
            d["url"] = urlmap[d["url"]]
            vals = {}
            for k in v_cols:
                if k == "id":
                    continue
                v = d.get(k)
                if k in ("from_visit", "segment_id", "originator_visit_id",
                         "originator_referring_visit", "originator_opener_visit", "app_id"):
                    v = 0
                elif k == "originator_cache_guid":
                    v = None
                vals[k] = v
            insert_row(cur, "visits", vals, tuple(vals))
            touched.add(d["url"])
            new_visits += 1
        for uid in touched:
            cur.execute("""UPDATE urls SET
                visit_count = (SELECT COUNT(*) FROM visits v WHERE v.url = urls.id),
                last_visit_time = (SELECT MAX(v.visit_time) FROM visits v WHERE v.url = urls.id)
                WHERE id = ?""", (uid,))
        main.commit()
        tu = cur.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
        tv = cur.execute("SELECT COUNT(*) FROM visits").fetchone()[0]
    return f"history: +{new_urls} urls -> {tu} total | +{new_visits} visits -> {tv} total"


def apply_cookies(plan, chrome_path, chr_key):
    with closing(sqlite3.connect(chrome_path)) as main:
        try:
            for d in plan["overwrite"]:
                main.execute("DELETE FROM cookies WHERE " +
                             " AND ".join(f"{c}=?" for c in COOKIE_KEY_COLS), cookie_key(d))
            for d in plan["overwrite"] + plan["insert"]:
                pt = d["_pt"]
                row = {k: v for k, v in d.items() if k in plan["cols"]}
                row["encrypted_value"] = v10_encrypt(chr_key, pt)
                insert_row(main, "cookies", row, plan["cols"])
                back = main.execute(
                    "SELECT encrypted_value FROM cookies WHERE " +
                    " AND ".join(f"{c}=?" for c in COOKIE_KEY_COLS), cookie_key(d)
                ).fetchone()[0]
                if v10_decrypt(chr_key, back) != pt:
                    raise ToolError(
                        f"round-trip verify failed for cookie {d['host_key']}{d['name']} "
                        "— cookies rolled back, nothing was written")
        except Exception:
            main.rollback()
            raise
        main.commit()
        total = main.execute("SELECT COUNT(*) FROM cookies").fetchone()[0]
    ins, ow = len(plan["insert"]), len(plan["overwrite"])
    xsite = sum(1 for d in plan["insert"] + plan["overwrite"]
                if d["has_cross_site_ancestor"] and not d["top_frame_site_key"])
    msg = (f"cookies: +{ins} new, {ow} overwritten (Arc fresher, {ins + ow}/{ins + ow} "
           f"verify ok), {plan['kept']} kept (Chrome fresher), {plan['expired']} expired, "
           f"{plan['failed']} undecryptable | chrome total: {total}")
    if xsite:
        msg += (f"\nnote: {xsite} imported third-party cookies will be dropped by Chrome "
                "on startup (usually trackers; not guaranteed to be login-free)")
    return msg


# ---------------------------------------------------------------- runner helpers

def snapshot_set(tmp, base, names, modes):
    paths = {}
    prefix = "arc" if base.startswith(ARC_BASE_DIR) else "chr"
    for n in names:
        dst = os.path.join(tmp, f"{prefix}_{n.replace(' ', '_')}")
        modes.add(backup_db(os.path.join(base, n), dst))
        paths[n] = dst
    return paths


def warn_if_best_effort(modes):
    if "best-effort" in modes:
        print("note: a browser is running, so some snapshots are best-effort "
              "(lock-free immutable reads, possibly slightly stale).\n"
              "      for a fully consistent migration, quit both Arc and Chrome first.")


def build_plans(what, arc_paths, chrome_paths, arc_key):
    plans = {}
    if "logins" in what:
        plans["logins"] = plan_logins(arc_paths["Login Data"],
                                      chrome_paths["Login Data"], arc_key)
    if "history" in what:
        plans["history"] = plan_history(arc_paths["History"], chrome_paths["History"])
    if "cookies" in what:
        plans["cookies"] = plan_cookies(arc_paths["Cookies"],
                                        chrome_paths["Cookies"], arc_key)
    return plans


def run_profile_diff(arc_prof, chr_prof, arc_key):
    arc_dir = os.path.join(ARC_BASE_DIR, arc_prof["dir"])
    chr_dir = os.path.join(CHROME_BASE_DIR, chr_prof["dir"])
    print(f"\n=== Diff: Arc [{arc_prof['dir']}: {arc_prof['name']}] -> Chrome [{chr_prof['dir']}: {chr_prof['name']}] ===")
    require_profile_files(arc_dir, chr_dir)
    with tempfile.TemporaryDirectory(prefix="arc-to-chrome-") as tmp:
        modes = set()
        arc_paths = snapshot_set(tmp, arc_dir, DB_FILES, modes)
        chr_paths = snapshot_set(tmp, chr_dir, DB_FILES, modes)
        plans = build_plans({"logins", "history", "cookies"}, arc_paths, chr_paths, arc_key)

        p = plans["logins"]
        rows = p["rows"]
        total = len(rows) + p["skipped"] + p["failed"]
        print(f"logins: {total} in Arc ({p['failed']} undecryptable/empty), "
              f"{p['skipped']} already in Chrome -> {len(rows)} to merge")
        for d in rows[:15]:
            print(f"  + {d['signon_realm'][:50]:50} {d['username_value'][:25]}")
        if len(rows) > 15:
            print(f"  ... and {len(rows) - 15} more")

        p = plans["history"]
        print(f"history: {p['arc_url_count']} urls / {p['arc_visit_count']} visits "
              f"in Arc -> {len(p['new_urls'])} urls, {p['new_visits']} visits new to Chrome")

        p = plans["cookies"]
        print(f"cookies: {len(p['insert'])} new, {len(p['overwrite'])} fresher in Arc "
              f"(will overwrite), {p['kept']} fresher in Chrome (kept), "
              f"{p['expired']} expired (skipped), {p['failed']} undecryptable")
        warn_if_best_effort(modes)


def run_profile_merge(arc_prof, chr_prof, what, dry_run=False, no_backup=False,
                      arc_key=None, chr_key=None):
    arc_dir = os.path.join(ARC_BASE_DIR, arc_prof["dir"])
    chr_dir = os.path.join(CHROME_BASE_DIR, chr_prof["dir"])
    print(f"\n=== Merge: Arc [{arc_prof['dir']}: {arc_prof['name']}] -> Chrome [{chr_prof['dir']}: {chr_prof['name']}] ===")
    require_profile_files(arc_dir, chr_dir)
    backup_dir = None
    if not dry_run and not no_backup:
        backup_dir = backup_chrome_profile(chr_dir)
        print(f"backed up Chrome profile DBs to {backup_dir}")

    with tempfile.TemporaryDirectory(prefix="arc-to-chrome-") as tmp:
        modes = set()
        names = {"logins": "Login Data", "history": "History", "cookies": "Cookies"}
        arc_paths = snapshot_set(tmp, arc_dir, [names[w] for w in what], modes)
        if dry_run:
            chr_paths = snapshot_set(tmp, chr_dir, [names[w] for w in what], modes)
        else:
            chr_paths = {n: os.path.join(chr_dir, n) for n in DB_FILES}
        warn_if_best_effort(modes)
        plans = build_plans(what, arc_paths, chr_paths, arc_key)
        try:
            if "logins" in what:
                print(apply_logins(plans["logins"], chr_paths["Login Data"], chr_key))
            if "history" in what:
                print(apply_history(plans["history"], arc_paths["History"],
                                    chr_paths["History"]))
            if "cookies" in what:
                print(apply_cookies(plans["cookies"], chr_paths["Cookies"], chr_key))
        except Exception:
            if backup_dir:
                print(f"\nmerge failed midway — Chrome DBs may be partially merged.",
                      file=sys.stderr)
                print(f"to roll back: quit Chrome, then copy ALL files from\n"
                      f"  {backup_dir}\nback into\n  {chr_dir}", file=sys.stderr)
            raise


# ---------------------------------------------------------------- commands

def cmd_profiles(_args):
    arc_profs = load_arc_profiles()
    chr_profs = load_chrome_profiles()
    matches = get_profile_matches()

    print("Arc Profiles:")
    for d, info in sorted(arc_profs.items()):
        spaces_str = f"Spaces: {', '.join(info['spaces'])}" if info['spaces'] else "No spaces"
        fav_str = f" | Favorites: {info['favorites_count']}" if info['favorites_count'] else ""
        print(f"  • {d:10} (Name: {info['name']}) -> {spaces_str}{fav_str}")

    print("\nChrome Profiles:")
    for d, info in sorted(chr_profs.items()):
        user_str = f" ({info['user_name']})" if info.get('user_name') else ""
        print(f"  • {d:10} (Name: {info['name']}{user_str})")

    print("\nAuto-detected Profile Matches (Arc -> Chrome):")
    if matches:
        for a, c in matches:
            print(f"  ✓ Arc [{a['dir']}: {a['name']}] ===> Chrome [{c['dir']}: {c['name']}]")
    else:
        print("  (No direct name matches found)")
    print("\nTip: Use `arc_to_chrome diff --all-profiles` or `arc_to_chrome merge --all-profiles` "
          "to operate on all matched profiles.")


def build_space_trees_for_spaces(space_list, favorites, no_unpinned=False, no_favorites=False):
    trees = []
    for s in space_list:
        children = list(s["pinned"])
        if not no_unpinned and s["unpinned"]:
            children.append({
                "type": "folder",
                "title": f"[{s['title']}: Today / Active Tabs]",
                "children": s["unpinned"]
            })
        trees.append({
            "type": "folder",
            "title": f"[Arc] {s['title']}",
            "children": children
        })
    if not no_favorites:
        p_dirs = {s["profile_dir"] for s in space_list}
        for p_dir in p_dirs:
            favs = favorites.get(p_dir, [])
            if favs:
                trees.append({
                    "type": "folder",
                    "title": "[Arc Favorites]",
                    "children": favs
                })
    return trees


def merge_spaces_for_pairs(pairs, dry_run=False, no_unpinned=False, no_favorites=False, space_filter=None):
    data = parse_arc_sidebar()
    spaces = data["spaces"]
    favorites = data["favorites"]
    if space_filter:
        spaces = [s for s in spaces if s["title"].lower() == space_filter.lower()]
    for a_p, c_p in pairs:
        p_spaces = [s for s in spaces if s["profile_dir"] == a_p["dir"]]
        favs = favorites.get(a_p["dir"], [])
        if not p_spaces and not favs:
            continue
        trees = build_space_trees_for_spaces(p_spaces, favorites, no_unpinned=no_unpinned, no_favorites=no_favorites)
        if not trees:
            continue
        chr_dir = os.path.join(CHROME_BASE_DIR, c_p["dir"])
        u_cnt, f_cnt = count_tree_nodes(trees)
        print(f"\nMerging {len(p_spaces)} space(s) into Chrome [{c_p['dir']}: {c_p['name']}]: "
              f"{u_cnt} URLs, {f_cnt} folders")
        if dry_run:
            for t in trees:
                print(f"  [folder] {t['title']} ({len(t.get('children', []))} items)")
        else:
            tgt, num = merge_chrome_bookmarks(chr_dir, trees, dry_run=False)
            print(f"  ✓ updated {tgt} (+{num} top-level folders)")


def cmd_diff(args):
    arc_key = get_key(ARC_KEYCHAIN)
    pairs = []
    if args.all_profiles:
        matches = get_profile_matches()
        if not matches:
            raise ToolError("no matching profiles found between Arc and Chrome")
        pairs = matches
    else:
        arc_p = resolve_profile(args.arc_profile, "arc")
        if args.chrome_profile:
            chr_p = resolve_profile(args.chrome_profile, "chrome")
        else:
            # Auto-match by name if available, else fallback to Default
            chr_profs = load_chrome_profiles()
            c_match = next((c for c in chr_profs.values() if c["name"].lower() == arc_p["name"].lower()), None)
            chr_p = c_match if c_match else resolve_profile("Default", "chrome")
            if c_match:
                print(f"note: auto-selected Chrome profile '{chr_p['dir']}' ({chr_p['name']})")
        pairs = [(arc_p, chr_p)]

    for a_p, c_p in pairs:
        run_profile_diff(a_p, c_p, arc_key)

    if getattr(args, "with_spaces", False):
        print("\n--- Spaces & Bookmarks Preview ---")
        merge_spaces_for_pairs(pairs, dry_run=True)


def cmd_merge(args):
    what = set(args.what.split(","))
    unknown = what - {"logins", "history", "cookies"}
    if unknown:
        raise ToolError(f"unknown --what values: {sorted(unknown)}")
    if args.dry_run:
        print("dry-run: merging against scratch copies; Chrome profile untouched")
    elif chrome_running():
        raise ToolError("Chrome is running. Quit it completely (Cmd+Q) before merge, "
                        "or use --dry-run to rehearse safely.")

    arc_key = chr_key = None
    if what & {"logins", "cookies"}:
        arc_key = get_key(ARC_KEYCHAIN)
        chr_key = get_key(CHROME_KEYCHAIN)

    pairs = []
    if args.all_profiles:
        matches = get_profile_matches()
        if not matches:
            raise ToolError("no matching profiles found between Arc and Chrome")
        pairs = matches
    else:
        arc_p = resolve_profile(args.arc_profile, "arc")
        if args.chrome_profile:
            chr_p = resolve_profile(args.chrome_profile, "chrome")
        else:
            chr_profs = load_chrome_profiles()
            c_match = next((c for c in chr_profs.values() if c["name"].lower() == arc_p["name"].lower()), None)
            chr_p = c_match if c_match else resolve_profile("Default", "chrome")
            if c_match:
                print(f"note: auto-selected Chrome profile '{chr_p['dir']}' ({chr_p['name']})")
        pairs = [(arc_p, chr_p)]

    for a_p, c_p in pairs:
        run_profile_merge(a_p, c_p, what, dry_run=args.dry_run,
                          no_backup=args.no_backup, arc_key=arc_key, chr_key=chr_key)

    if getattr(args, "with_spaces", False):
        print("\n--- Merging Spaces & Bookmarks ---")
        merge_spaces_for_pairs(pairs, dry_run=args.dry_run)

    if args.dry_run:
        print("\ndry-run done: nothing was written to Chrome profile(s)")


def cmd_spaces(args):
    data = parse_arc_sidebar()
    spaces = data["spaces"]
    favorites = data["favorites"]
    chr_profs = load_chrome_profiles()

    if args.spaces_cmd == "list":
        print("Arc Spaces & Profiles:")
        print(f"{'Space':<16} {'Arc Profile':<24} {'Chrome Match':<24} {'Pinned':<22} {'Unpinned':<10}")
        print("-" * 100)
        for s in spaces:
            p_name = s["profile_name"]
            p_dir = s["profile_dir"]
            arc_p_str = f"{p_dir} ({p_name})"
            c_match = next((c for c in chr_profs.values() if c["name"].lower() == p_name.lower()), None)
            c_str = f"{c_match['dir']} ({c_match['name']})" if c_match else "-"
            pu, pf = count_tree_nodes(s["pinned"])
            uu, _ = count_tree_nodes(s["unpinned"])
            fav_count = len(favorites.get(p_dir, []))
            pin_desc = f"{pu} urls, {pf} dirs"
            if fav_count:
                pin_desc += f" (+{fav_count}⭐)"
            print(f"{s['title']:<16} {arc_p_str:<24} {c_str:<24} {pin_desc:<22} {uu} tabs")
        print("-" * 100)
        return

    # Filter spaces & favorites
    target_spaces = spaces
    if getattr(args, "space", None):
        target_spaces = [s for s in target_spaces if s["title"].lower() == args.space.lower()]
        if not target_spaces:
            raise ToolError(f"Space '{args.space}' not found. Available spaces: "
                            f"{', '.join(s['title'] for s in spaces)}")
    if getattr(args, "arc_profile", None):
        arc_p = resolve_profile(args.arc_profile, "arc")
        target_spaces = [s for s in target_spaces if s["profile_dir"] == arc_p["dir"]]

    if args.spaces_cmd == "export":
        trees = build_space_trees_for_spaces(target_spaces, favorites,
                                             no_unpinned=getattr(args, "no_unpinned", False),
                                             no_favorites=getattr(args, "no_favorites", False))
        html_content = generate_html_bookmarks(trees)
        out_path = os.path.expanduser(args.output)
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        total_urls, total_dirs = count_tree_nodes(trees)
        print(f"Exported {len(target_spaces)} space(s) ({total_urls} URLs, {total_dirs} folders) to:\n  {out_path}")
        print("To import into Chrome: Chrome -> Bookmarks -> Import Bookmarks and Settings -> Select HTML file.")

    elif args.spaces_cmd == "merge":
        if not args.dry_run and chrome_running():
            raise ToolError("Chrome is running. Quit it completely (Cmd+Q) before merge, "
                            "or use --dry-run to rehearse safely.")

        if getattr(args, "all_profiles", False):
            matches = get_profile_matches()
            merge_spaces_for_pairs(matches, dry_run=args.dry_run,
                                   no_unpinned=getattr(args, "no_unpinned", False),
                                   no_favorites=getattr(args, "no_favorites", False),
                                   space_filter=getattr(args, "space", None))
        else:
            if getattr(args, "chrome_profile", None):
                chr_p = resolve_profile(args.chrome_profile, "chrome")
            else:
                if target_spaces:
                    first_p_dir = target_spaces[0]["profile_dir"]
                    first_p_name = target_spaces[0]["profile_name"]
                    c_match = next((c for c in chr_profs.values() if c["name"].lower() == first_p_name.lower()), None)
                    chr_p = c_match if c_match else resolve_profile("Default", "chrome")
                else:
                    chr_p = resolve_profile("Default", "chrome")

            if target_spaces:
                arc_p = resolve_profile(target_spaces[0]["profile_dir"], "arc")
            else:
                arc_p = resolve_profile("Default", "arc")

            merge_spaces_for_pairs([(arc_p, chr_p)], dry_run=args.dry_run,
                                   no_unpinned=getattr(args, "no_unpinned", False),
                                   no_favorites=getattr(args, "no_favorites", False),
                                   space_filter=getattr(args, "space", None))
            if args.dry_run:
                print("dry-run: previewing bookmark folders to create:")
                for t in trees:
                    print(f"  [folder] {t['title']} ({len(t.get('children', []))} items)")
            else:
                tgt, num = merge_chrome_bookmarks(chr_dir, trees, dry_run=False)
                print(f"✓ successfully merged into {tgt} (+{num} top-level folders)")


def cmd_selftest(_args):
    key = os.urandom(16)
    for pt in (b"", b"a", b"sixteen_bytes!!!", os.urandom(100)):
        assert v10_decrypt(key, v10_encrypt(key, pt)) == pt
    assert v10_decrypt(key, b"plain") is None
    assert v10_decrypt(key, b"v10" + b"\x00" * 15) is None
    bad = b"A" * 13 + b"\x01\x02\x03"
    ct = b"v10" + AES.new(key, AES.MODE_CBC, iv=b" " * 16).encrypt(bad)
    assert v10_decrypt(key, ct) is None
    trials = 1000
    enc = v10_encrypt(key, b"secret")
    passed = sum(1 for _ in range(trials)
                 if v10_decrypt(os.urandom(16), enc) is not None)
    assert passed / trials < 0.03, f"wrong-key false-success rate too high: {passed}/{trials}"
    print(f"selftest ok: round-trips pass; padding tamper rejected; "
          f"wrong-key false-success {passed}/{trials}")


def main():
    p = argparse.ArgumentParser(
        prog="arc_to_chrome",
        description="Merge Arc logins, history, cookies, and Spaces into Chrome (macOS, offline).")
    sub = p.add_subparsers(dest="cmd", required=True)

    # profiles
    sub.add_parser("profiles", help="list Arc & Chrome profiles, Spaces, and auto-detected pairings")

    # diff
    p_diff = sub.add_parser("diff", help="preview what would be merged (read-only)")
    p_diff.add_argument("--arc-profile", help="Arc profile name, directory, or space name (default: Default)")
    p_diff.add_argument("--chrome-profile", help="Chrome profile name or directory (default: auto-match or Default)")
    p_diff.add_argument("--all-profiles", action="store_true", help="run diff across all matched profiles")
    p_diff.add_argument("--with-spaces", action="store_true", help="also preview Arc Spaces / Bookmarks")

    # merge
    p_merge = sub.add_parser("merge", help="perform the merge (Chrome must be quit)")
    p_merge.add_argument("--what", default="logins,history,cookies",
                         help="comma-separated subset of: logins,history,cookies")
    p_merge.add_argument("--arc-profile", help="Arc profile name, directory, or space name (default: Default)")
    p_merge.add_argument("--chrome-profile", help="Chrome profile name or directory (default: auto-match or Default)")
    p_merge.add_argument("--all-profiles", action="store_true", help="merge all matched profiles sequentially")
    p_merge.add_argument("--with-spaces", action="store_true",
                         help="also merge Arc Spaces into Chrome Bookmarks in the same run")
    p_merge.add_argument("--dry-run", action="store_true",
                         help="run the full pipeline against scratch copies, write nothing")
    p_merge.add_argument("--no-backup", action="store_true",
                         help="skip backing up Chrome's DBs first")

    # spaces
    p_spaces = sub.add_parser("spaces", help="inspect, export, or merge Arc Spaces into Chrome Bookmarks")
    spaces_sub = p_spaces.add_subparsers(dest="spaces_cmd", required=True)

    spaces_sub.add_parser("list", help="list all Arc Spaces, tab counts, and linked profiles")

    s_export = spaces_sub.add_parser("export", help="export Arc Spaces to Netscape Bookmarks HTML file")
    s_export.add_argument("-o", "--output", default=os.path.expanduser("~/Downloads/arc_spaces.html"),
                          help="destination HTML file (default: ~/Downloads/arc_spaces.html)")
    s_export.add_argument("--space", help="filter by specific Arc space name")
    s_export.add_argument("--arc-profile", help="filter by Arc profile name or directory")
    s_export.add_argument("--no-unpinned", action="store_true", help="exclude unpinned/today's tabs")
    s_export.add_argument("--no-favorites", action="store_true", help="exclude profile favorites")

    s_merge = spaces_sub.add_parser("merge", help="merge Arc Spaces directly into Chrome profile Bookmarks")
    s_merge.add_argument("--chrome-profile", help="destination Chrome profile name or directory")
    s_merge.add_argument("--arc-profile", help="source Arc profile name or directory")
    s_merge.add_argument("--space", help="filter to specific space name")
    s_merge.add_argument("--all-profiles", action="store_true",
                         help="merge each Arc profile's spaces into its matching Chrome profile")
    s_merge.add_argument("--no-unpinned", action="store_true", help="exclude unpinned/today's tabs")
    s_merge.add_argument("--no-favorites", action="store_true", help="exclude profile favorites")
    s_merge.add_argument("--dry-run", action="store_true",
                         help="preview bookmark trees to be created without writing")

    # selftest
    sub.add_parser("selftest", help="crypto sanity checks")

    args = p.parse_args()
    try:
        {
            "profiles": cmd_profiles,
            "diff": cmd_diff,
            "merge": cmd_merge,
            "spaces": cmd_spaces,
            "selftest": cmd_selftest
        }[args.cmd](args)
    except ToolError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
