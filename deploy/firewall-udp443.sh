#!/usr/bin/env bash
# firewall-udp443.sh — block inbound UDP/443 so clients fall back to TCP TLS when
# protocols.quic = false (design doc C-2). Keeps QUIC/HTTP-3 from bypassing the
# TCP intercept path on constrained VMs. Prefers nftables, falls back to iptables.
set -euo pipefail

ACTION="${1:-block}"   # block | unblock
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
log() { printf '[fw-udp443] %s\n' "$*"; }

if command -v nft >/dev/null 2>&1; then
  case "$ACTION" in
    block)
      nft list table inet mirage_chaff >/dev/null 2>&1 || nft add table inet mirage_chaff
      nft 'add chain inet mirage_chaff input { type filter hook input priority 0 ; }' 2>/dev/null || true
      nft add rule inet mirage_chaff input udp dport 443 drop
      log "nftables: dropping inbound UDP/443" ;;
    unblock)
      nft delete table inet mirage_chaff 2>/dev/null || true
      log "nftables: removed UDP/443 block" ;;
    *) echo "usage: $0 [block|unblock]" >&2; exit 2 ;;
  esac
elif command -v iptables >/dev/null 2>&1; then
  case "$ACTION" in
    block)
      iptables  -C INPUT -p udp --dport 443 -j DROP 2>/dev/null || iptables  -A INPUT -p udp --dport 443 -j DROP
      command -v ip6tables >/dev/null && { ip6tables -C INPUT -p udp --dport 443 -j DROP 2>/dev/null || ip6tables -A INPUT -p udp --dport 443 -j DROP; }
      log "iptables: dropping inbound UDP/443 (v4+v6)" ;;
    unblock)
      iptables  -D INPUT -p udp --dport 443 -j DROP 2>/dev/null || true
      command -v ip6tables >/dev/null && ip6tables -D INPUT -p udp --dport 443 -j DROP 2>/dev/null || true
      log "iptables: removed UDP/443 block" ;;
    *) echo "usage: $0 [block|unblock]" >&2; exit 2 ;;
  esac
else
  echo "neither nft nor iptables found" >&2; exit 1
fi
