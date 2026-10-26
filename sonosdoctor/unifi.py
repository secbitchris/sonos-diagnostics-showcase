"""Pure vendor-prefix lookup; no controller connection code."""
SONOS_OUIS = {"00:0e:58", "5c:aa:fd", "94:9f:3e", "78:28:ca", "b8:e9:37",
              "34:7e:5c", "48:a6:b8", "f0:f6:c1", "38:42:0b", "54:2a:1b",
              "c4:38:75", "68:54:fd", "e8:5d:86", "8c:4c:ad"}

def is_sonos_oui(mac):
    return bool(mac) and mac.lower()[:8] in SONOS_OUIS
