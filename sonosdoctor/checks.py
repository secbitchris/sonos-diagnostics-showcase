"""Findings engine — every check earned from a real incident.

Severities: crit / warn / info. Each finding: {severity, code, subject,
message}. Checks needing history (reboots, disappearances) take the
previous snapshot; checks needing UniFi skip silently without it.
"""

THRESHOLDS = {
    "loss_warn_pct": 0.1,
    "loss_crit_pct": 20.0,
    "jitter_warn_ms": 30.0,
    "clean_floor_ms": 5.0,

    "tail_ratio": 25,

    "mesh_weak_db": 15,
    "ani_warn": 9,
    "ani_warn_bridge": 10,

    "ani_busy_neighbours": 8,


    "ani_strong_db": 40,
    "noise_floor_warn_dbm": -87,
    "switch_prio_weak": 32768,
    "asym_db": 15,
    "asym_quiet_floor_db": 45,


    "foreign_db": 25,
}


def _f(sev, code, subject, message):
    return {"severity": sev, "code": code, "subject": subject, "message": message}


def run_checks(snap, previous=None, th=None, known=None):
    th = {**THRESHOLDS, **(th or {})}
    F = []
    devices = snap.get("devices", [])
    fleet_macs = {(d.get("mac") or "").lower() for d in devices if d.get("mac")}
    fleet_radio = {d.get("radio_mac") for d in devices if d.get("radio_mac")}
    by_mac = {(d.get("mac") or "").lower(): d for d in devices}

    def label(d):
        return f"{d.get('room') or '?'} ({d.get('ip') or d.get('mac') or '?'})"


    roots = {}
    for d in devices:
        s = d.get("stp") or {}
        if s.get("root_mac"):
            roots.setdefault((s.get("root_prio"), s["root_mac"]), []).append(d)
    for (prio, rmac), agreeing in roots.items():
        if rmac in fleet_macs or rmac in fleet_radio:
            F.append(_f("crit", "stp-root-is-sonos", rmac,
                        f"A Sonos player ({rmac}, prio {prio}) is the spanning-tree "
                        f"ROOT BRIDGE — {len(agreeing)} player(s) agree. Your LAN "
                        f"topology is being decided by a speaker. Lower a core "
                        f"switch's STP priority below 32768."))
    if len(roots) > 1:
        views = "; ".join(f"{m} (prio {p}, {len(v)} players)"
                          for (p, m), v in roots.items())
        F.append(_f("warn", "stp-root-disagreement", "fleet",
                    f"Players disagree on the STP root: {views}. Topology may be "
                    f"mid-reconvergence, or part of the mesh is partitioned."))


    uni = snap.get("unifi") or {}
    for r in (uni.get("stp") or {}).get("roots", []):
        if not r.get("is_unifi_device"):
            F.append(_f("crit", "stp-root-not-switch", r.get("mac"),
                        f"Switches report root bridge {r.get('mac')} "
                        f"({r.get('identified_as')}) which is not a managed switch "
                        f"({r.get('agreeing_switches')} switches agree)."))
    weak = [n for n, v in (uni.get("stp") or {}).get("priorities", {}).items()
            if v is not None and v >= th["switch_prio_weak"]]
    if weak:
        F.append(_f("warn", "switch-priority-weak", ", ".join(sorted(weak)[:6]),
                    f"{len(weak)} switch(es) at STP priority >= "
                    f"{th['switch_prio_weak']} can lose the root election to a "
                    f"Sonos player (Sonos advertises ~32768)."))

    strong_nbrs = {}
    for e in snap.get("matrix", []):
        if (e.get("from_db") or 0) >= th["ani_strong_db"]:
            k = (e.get("src_mac") or "").lower()
            strong_nbrs[k] = strong_nbrs.get(k, 0) + 1


    for d in devices:
        p = d.get("ping") or {}


        _u = d.get("unifi") or {}
        if d.get("tcp_1400_open") is False:
            if _u and (_u.get("uptime") or 0) > 0:
                F.append(_f("crit", "link-up-but-dead", label(d),
                            f"Port 1400 is closed, but the controller still "
                            f"shows the client up (uptime {_u.get('uptime')}s) "
                            f"— stale controller state or a one-way path. The "
                            f"Sonos app cannot control this player."))
            else:
                F.append(_f("crit", "port-1400-closed", label(d),
                            "Responds to discovery/ping but port 1400 is closed "
                            "— the Sonos app cannot control this player."))
        if d.get("ssdp_missing"):
            F.append(_f("warn", "ssdp-missing", label(d),
                        "In the household (per /support/review) but did not answer "
                        "SSDP discovery — multicast may be broken on its segment, "
                        "or the player is offline."))
        loss = p.get("loss_pct") or 0
        if loss >= th["loss_crit_pct"]:
            F.append(_f("crit", "packet-loss", label(d), f"{loss}% packet loss."))
        elif loss > th["loss_warn_pct"]:
            F.append(_f("warn", "packet-loss", label(d), f"{loss}% packet loss."))


        mn, mx = p.get("min_ms"), p.get("max_ms")
        if (mn is not None and mx is not None and not loss
                and mn <= th["clean_floor_ms"]
                and mx >= mn * th["tail_ratio"]
                and (p.get("jitter_ms") or 0) > th["jitter_warn_ms"]):
            F.append(_f("warn", "tail-only-latency", label(d),
                        f"Tail-only: floor {mn} ms but peak {mx} ms in the same "
                        f"burst, 0% loss ({mx / mn:.0f}x spread). The link "
                        f"reaches wire speed and loses nothing — this is "
                        f"queueing or airtime starvation, NOT signal. Another "
                        f"access point on the same channel will not fix it; "
                        f"look at what else is using the air, or move channel."))
        elif (p.get("jitter_ms") or 0) > th["jitter_warn_ms"]:


            F.append(_f("warn", "high-jitter", label(d),
                        f"Jitter {p['jitter_ms']} ms (avg {p.get('avg_ms')} ms) — "
                        f"grouped-room audio drops start around here."))
        is_bridge = "boost" in (d.get("model") or "").lower()\
            or "bridge" in (d.get("model") or "").lower()


        nbrs = strong_nbrs.get((d.get("mac") or "").lower())
        floor_raised = nf_val = d.get("noise_floor")
        floor_raised = nf_val is not None and nf_val >= th["noise_floor_warn_dbm"]
        busy = nbrs is not None and nbrs >= th["ani_busy_neighbours"]
        if (d.get("ani") or 0) >= th["ani_warn_bridge" if is_bridge else "ani_warn"]\
                and not (busy and not floor_raised):
            why = (" and the noise floor is raised" if floor_raised
                   else f" on a node hearing only {nbrs} strong neighbour(s)")
            F.append(_f("warn", "high-ani", label(d),
                        f"OFDM ANI level {d['ani']}/9{why} — the radio is "
                        f"fighting 2.4 GHz interference on ch "
                        f"{d.get('channel')}. (ANI alone tracks how much "
                        f"traffic a radio arbitrates around; this one is "
                        f"corroborated.)"))
        nf = d.get("noise_floor")
        if nf is not None and nf >= th["noise_floor_warn_dbm"]:
            F.append(_f("warn", "noise-floor-high", label(d),
                        f"Noise floor {nf} dBm (healthy is <= -90)."))
        u = d.get("unifi") or {}
        if u.get("name") and d.get("room"):
            alias = u["name"].lower()
            if "sonos" not in alias and d["room"].lower()[:6] not in alias:
                F.append(_f("info", "alias-oui-mismatch", label(d),
                            f"Controller alias '{u['name']}' does not look like "
                            f"this Sonos ('{d['room']}') — labels lie; verify "
                            f"identity by OUI/causality before trusting names."))


    edge_by_pair = {}
    for e in snap.get("matrix", []):
        edge_by_pair[(e["src_mac"], e["dst_mac"])] = e
    radio_to_mac = {d.get("radio_mac"): (d.get("mac") or "").lower()
                    for d in devices if d.get("radio_mac")}
    for d in devices:
        for port in (d.get("stp") or {}).get("ports", []):


            if (port.get("state") != "forwarding"
                    or port.get("remote_state") != "forwarding"
                    or not port.get("tunnel_to")):
                continue
            peer = radio_to_mac.get(port["tunnel_to"], port["tunnel_to"])
            e = edge_by_pair.get(((d.get("mac") or "").lower(), peer))
            if e and 0 < e["from_db"] < th["mesh_weak_db"]:
                peer_d = by_mac.get(peer)
                F.append(_f("warn", "weak-mesh-path", label(d),
                            f"Forwarding SonosNet tunnel to "
                            f"{label(peer_d) if peer_d else peer} at only "
                            f"{e['from_db']} dB — audio rides this weak link."))


    if snap.get("discovery_method") == "sweep" and devices:
        F.append(_f("warn", "multicast-broken", "network",
                    f"SSDP multicast found 0 players but a TCP sweep found "
                    f"{snap.get('discovered_count')} — multicast is filtered "
                    f"on this segment. The Sonos app itself will struggle to "
                    f"discover players here (IGMP snooping / mDNS-SSDP "
                    f"filtering is the usual culprit)."))


    for d in devices:
        if d.get("behind_extender") == 1:
            F.append(_f("warn", "behind-wifi-extender", label(d),
                        "This player sits behind a WiFi extender/repeater — "
                        "the classic cause of Sonos drops and ghost players "
                        "(extenders mangle multicast and double latency). "
                        "Move it to the main AP or wire it."))
        b = d.get("battery")


        if b and isinstance(b.get("level"), int) and b["level"] <= 20\
                and str(b.get("power_source", "")).upper() == "BATTERY":
            F.append(_f("warn", "low-battery", label(d),
                        f"Battery at {b['level']}% and not on external power "
                        f"(health {b.get('health')})."))
    households = snap.get("households") or []
    if len(households) > 1:
        F.append(_f("warn", "multiple-households", f"{len(households)} systems",
                    f"{len(households)} separate Sonos households share this "
                    f"LAN — speakers in different households cannot see or "
                    f"group with each other. Usually an S1/S2 split or a "
                    f"half-migrated system."))
    gens = {d.get("swgen") for d in devices if d.get("swgen")}
    if len(gens) > 1:
        F.append(_f("warn", "mixed-generations", "fleet",
                    f"Both S1 and S2 generation players are present "
                    f"(SWGen {sorted(gens)}) — they cannot group together "
                    f"unless the whole system runs S1."))


    channels = {d.get("channel") for d in devices
                if d.get("channel") and (d.get("wifi_mode") or "").startswith("SONOSNET")}
    if len(channels) > 1:
        F.append(_f("warn", "channel-mismatch", "fleet",
                    f"SonosNet players report different channels: "
                    f"{sorted(channels)} — mesh may be split mid-migration."))


    bridges = snap.get("bridge_points") or {}
    stp_unhealthy = any(f["code"].startswith("stp-root") or
                        f["code"] == "switch-priority-weak" for f in F)
    if len(bridges) > 1 and stp_unhealthy:
        F.append(_f("warn", "multiple-bridge-points", f"{len(bridges)} locations",
                    f"{len(bridges)} wired Sonos bridge the mesh onto the LAN "
                    f"and the spanning-tree election is NOT healthy — these "
                    f"redundant paths are only safe while it is: "
                    f"{'; '.join(sorted(bridges))}"))


    tree = snap.get("mesh_tree") or {}
    for mac, node in tree.items():
        parent = node.get("parent")
        if not parent or node.get("via") != "sonosnet":
            continue
        d, pd = by_mac.get(mac), by_mac.get(parent)
        fwd = edge_by_pair.get((mac, parent))
        rev = edge_by_pair.get((parent, mac))

        if fwd and rev and fwd["from_db"] and rev["from_db"] and\
                abs(fwd["from_db"] - rev["from_db"]) >= th["asym_db"] and\
                min(fwd["from_db"], rev["from_db"]) < th["asym_quiet_floor_db"]:
            F.append(_f("warn", "asymmetric-path",
                        label(d) if d else mac,
                        f"Uplink to {label(pd) if pd else parent} is asymmetric: "
                        f"hears parent at {fwd['from_db']} dB but is heard at "
                        f"{rev['from_db']} dB — points at local noise, antenna "
                        f"placement, or obstruction at the quieter end."))


    gw = set((uni.get("gateways") or []))
    uplink_ports = {tuple(x) for x in (uni.get("uplink_ports") or [])}
    switch_ports = uni.get("switch_ports") or {}
    for mac, node in tree.items():
        if node.get("via") != "sonosnet":
            continue
        d = by_mac.get(mac)
        u = (d or {}).get("unifi") or {}
        if not u.get("switch"):
            continue

        if u["switch"] in gw or (u["switch"], u.get("sw_port")) in uplink_ports:
            continue


        real_ports = switch_ports.get(u["switch"])
        if (real_ports and u.get("sw_port") is not None
                and u["sw_port"] not in real_ports):
            continue
        cur, seen = mac, set()
        while tree.get(cur, {}).get("parent") and cur not in seen:
            seen.add(cur)
            cur = tree[cur]["parent"]
        root_u = (by_mac.get(cur) or {}).get("unifi") or {}
        if not root_u.get("switch") or not tree.get(cur, {}).get("via") == "lan":
            continue
        if (u["switch"], u.get("sw_port")) != (root_u["switch"],
                                               root_u.get("sw_port")):
            rd = by_mac.get(cur)
            F.append(_f("info", "controller-path-mismatch", label(d),
                        f"Controller learned this MAC on {u['switch']} port "
                        f"{u.get('sw_port')}, but its mesh uplink chain ends at "
                        f"{label(rd) if rd else cur} on {root_u['switch']} port "
                        f"{root_u.get('sw_port')} — stale controller entry, or "
                        f"an undiscovered bridge in the path."))

    heard_foreign = {}
    for e in snap.get("matrix", []):
        if not e.get("dst_resolved") and e["from_db"] >= th["foreign_db"]:
            heard_foreign.setdefault(e["dst_mac"], []).append(
                (e["src_mac"], e["from_db"]))
    from .unifi import is_sonos_oui
    for fmac, hearers in heard_foreign.items():
        loudest = max(h[1] for h in hearers)
        vendor = ("its OUI is Sonos — a neighbour's system on the same "
                  "channel, or a forgotten/unregistered unit"
                  if is_sonos_oui(fmac) else
                  "its OUI is NOT Sonos — likely a non-Sonos 2.4 GHz device")
        F.append(_f("info", "unknown-mesh-neighbor", fmac,
                    f"Radio {fmac} is not in this household but "
                    f"{len(hearers)} player(s) hear it (loudest {loudest} dB); "
                    f"{vendor}. It competes for the same airtime."))


    rd = snap.get("radio_derivation") or {}
    for v in rd.get("violations", []):
        F.append(_f("warn", "radio-mac-derivation-broken", v.get("mac"),
                    f"{v.get('ip')} reports radio {v.get('radio_mac')}, which is "
                    f"neither of the derived {', '.join(v.get('expected') or [])}. "
                    f"Mesh resolution assumes radio = ethernet + 1 (+ 2 for a "
                    f"second radio); this player breaks it, so foreign-neighbour "
                    f"findings may be wrong until the rule is revisited."))

    for mac, info in (known or {}).items():
        if mac in by_mac or not info.get("missing_for"):
            continue
        n = info["missing_for"]
        F.append(_f("warn", "device-missing",
                    f"{info.get('room')} ({info.get('ip')})",
                    f"Gone for {n} consecutive snapshot(s) — still not "
                    f"answering. Reported every snapshot it stays missing, not "
                    f"only the one it vanished in."))


    if previous:
        prev_by_mac = {(d.get("mac") or "").lower(): d
                       for d in previous.get("devices", [])}
        for mac, pd in prev_by_mac.items():
            d = by_mac.get(mac)
            if d is None:
                if not (known or {}).get(mac):
                    F.append(_f("warn", "device-missing",
                                f"{pd.get('room')} ({pd.get('ip')})",
                                "Present in the previous snapshot, gone now."))
                continue
            b0, b1 = pd.get("boot_seq"), d.get("boot_seq")


            u0 = (pd.get("unifi") or {}).get("uptime")
            u1 = (d.get("unifi") or {}).get("uptime")
            rebooted = ((u0 is not None and u1 is not None and u1 < u0)
                        or d.get("tcp_1400_open") is False)
            if b0 is not None and b1 is not None and b1 > b0 and not rebooted:
                F.append(_f("info", "bootseq-advanced", label(d),
                            f"BootSeq {b0} → {b1} without any sign of a restart "
                            f"(uptime kept climbing, stayed reachable) — a UPnP "
                            f"re-announce, typically a topology or group change. "
                            f"NOT a reboot."))
            elif b0 is not None and b1 is not None and b1 > b0:
                F.append(_f("info", "reboot-detected", label(d),
                            f"BootSeq {b0} → {b1} — rebooted "
                            f"{b1 - b0} time(s) since the previous snapshot."))
        prev_tree = previous.get("mesh_tree") or {}
        for mac, node in (snap.get("mesh_tree") or {}).items():
            old = prev_tree.get(mac)
            if old and old.get("parent") and node.get("parent")\
                    and old["parent"] != node["parent"]:
                d = by_mac.get(mac)
                oldp, newp = by_mac.get(old["parent"]), by_mac.get(node["parent"])
                F.append(_f("info", "mesh-reparented", label(d) if d else mac,
                            f"Uplink moved: "
                            f"{label(oldp) if oldp else old['parent']} → "
                            f"{label(newp) if newp else node['parent']}. "
                            f"Occasional moves are normal; frequent re-parenting "
                            f"is the signature of a marginal RF path."))
    return F
