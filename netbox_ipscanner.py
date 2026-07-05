import socket
import ipaddress

import networkscan
from django.db import transaction

from extras.scripts import Script, BooleanVar, StringVar
from ipam.choices import PrefixStatusChoices, IPAddressStatusChoices
from ipam.models import Prefix, IPAddress


class IpScan(Script):
    """Scans available prefixes and updates IP addresses in the IPAM module."""

    # ── Script variables (shown in UI) ────────────────────────
    TagBasedScanning = BooleanVar(
        label="Tag Based Scanning?",
        default=False,
        description="Enable Tag Based Scanning to scan only Subnets with the specified Tag.",
    )
    tag = StringVar(
        max_length=20,
        label="Scan Tag?",
        default="scan",
        description="Specify the Tag to filter Subnets to be scanned",
        required=True,
    )

    class Meta:
        name = "IP Scanner"
        description = "Scans available prefixes and updates IP addresses in IPAM Module"
        job_timeout = 3600  # 1 hour — large scans may take a while

    # ── Helpers ───────────────────────────────────────────────

    @staticmethod
    def _reverse_lookup(ip):
        """DNS reverse lookup with controlled failure."""
        try:
            result = socket.gethostbyaddr(str(ip))
        except Exception:
            return ''
        return result[0] if result[0] else ''

    @staticmethod
    def _get_existing_ips(prefix_obj):
        """
        Batch-fetch all IPAddress objects belonging to a prefix in a single query.
        Returns a dict mapping bare IP strings (without mask) to IPAddress objects.
        """
        # net_contained_or_equal matches all IP addresses contained within the network
        qs = IPAddress.objects.filter(
            address__net_contained_or_equal=str(prefix_obj.prefix)
        )
        result = {}
        for ip in qs:
            # address is stored as "10.0.0.1/24" — strip the mask
            bare_addr = str(ip.address).split('/')[0]
            result[bare_addr] = ip
        return result

    # ── Main ──────────────────────────────────────────────────

    def run(self, data, commit):
        """
        Scan all prefixes via ICMP and sync results into NetBox IPAM.

        When commit=False (check mode), only log what *would* happen —
        no database writes are performed.
        """
        prefixes = Prefix.objects.all()
        total_prefixes = prefixes.count()
        self.log_info(f"Found {total_prefixes} prefixes to evaluate.")

        for prefix in prefixes:

            # ── Tag-based filtering ──
            if data['TagBasedScanning']:
                has_tag = prefix.tags.filter(name=data['tag']).exists()
                if not has_tag:
                    self.log_debug(
                        f'Checking {prefix.prefix}... Tag "{data["tag"]}" not found.'
                    )
                    self.log_warning(
                        f"Scan of {prefix.prefix} NOT done "
                        f"(missing '{data['tag']}' tag)"
                    )
                    continue

            # ── Skip reserved prefixes ──
            if prefix.status == PrefixStatusChoices.STATUS_RESERVED:
                self.log_warning(f"Scan of {prefix.prefix} NOT done (is Reserved)")
                continue

            # ── Skip container prefixes (no usable hosts) ──
            if prefix.status == PrefixStatusChoices.STATUS_CONTAINER:
                self.log_debug(f"Scan of {prefix.prefix} NOT done (is Container)")
                continue

            self.log_debug(
                f'Checking {prefix.prefix}... '
                f'Tags: {list(prefix.tags.values_list("name", flat=True))}'
            )

            # ── Build network & scan ──
            try:
                network = ipaddress.ip_network(str(prefix.prefix), strict=False)
            except (ValueError, ipaddress.AddressValueError):
                self.log_warning(
                    f"Scan of {prefix.prefix} NOT done (invalid network address)"
                )
                continue
            if network.version != 4:
                self.log_warning(
                    f"Scan of {prefix.prefix} NOT done (IPv6 not supported)"
                )
                continue
            mask = '/' + str(network.prefixlen)

            try:
                scan = networkscan.Networkscan(str(prefix.prefix))
                scan.run()
            except Exception as e:
                self.log_failure(f"Scan of {prefix.prefix} FAILED: {e}")
                continue
            self.log_info(f'Scan of {prefix.prefix} done.')

            # ── Batch-fetch ALL existing IPs for this prefix (1 query!) ──
            existing_ips = self._get_existing_ips(prefix)
            alive_hosts = set(str(h) for h in scan.list_of_hosts_found)

            # ── Process: deprecate non-responding + update/create responding ──
            updates = []
            creates = []

            for addr_str, netbox_ip in existing_ips.items():
                if addr_str in alive_hosts:
                    # Alive & in NetBox → mark active, check DNS name
                    name = self._reverse_lookup(addr_str)
                    needs_update = False
                    if netbox_ip.status != IPAddressStatusChoices.STATUS_ACTIVE:
                        netbox_ip.status = IPAddressStatusChoices.STATUS_ACTIVE
                        needs_update = True
                    if netbox_ip.dns_name != name:
                        netbox_ip.dns_name = name
                        needs_update = True
                        self.log_success(f'Name for {addr_str} updated to {name}')
                    if needs_update:
                        updates.append(netbox_ip)
                else:
                    # In NetBox but not responding → mark deprecated
                    # Only deprecate if currently active/dhcp/slaac (not already deprecated/reserved)
                    if netbox_ip.status not in (
                        IPAddressStatusChoices.STATUS_DEPRECATED,
                        IPAddressStatusChoices.STATUS_RESERVED,
                    ):
                        self.log_warning(
                            f"Host {netbox_ip} exists in netbox "
                            f"but not responding --> DEPRECATED"
                        )
                        netbox_ip.status = IPAddressStatusChoices.STATUS_DEPRECATED
                        updates.append(netbox_ip)

            # ── Create new IPs for alive hosts not yet in NetBox ──
            for addr_str in alive_hosts:
                if addr_str not in existing_ips:
                    name = self._reverse_lookup(addr_str)
                    ip_mask = addr_str + mask
                    creates.append(IPAddress(
                        address=ip_mask,
                        status=IPAddressStatusChoices.STATUS_ACTIVE,
                        dns_name=name,
                    ))
                    self.log_success(f'Added {addr_str} - {name}')

            if not alive_hosts:
                self.log_warning(f'No host found in network {prefix.prefix}')
            else:
                self.log_success(f'IPs found: {scan.list_of_hosts_found}')

            # ── Apply changes in a single transaction ──
            if commit:
                with transaction.atomic():
                    for obj in updates:
                        obj.save()
                    for obj in creates:
                        try:
                            obj.save()
                        except Exception as e:
                            self.log_failure(
                                f'Adding {obj.address} - {obj.dns_name} FAILED: {e}'
                            )
            else:
                # Dry-run — just log what would happen
                for obj in updates:
                    self.log_info(f'[DRY-RUN] Would update {obj.address}')
                for obj in creates:
                    self.log_info(f'[DRY-RUN] Would create {obj.address}')
