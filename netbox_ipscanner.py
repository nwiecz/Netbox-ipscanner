from extras.scripts import Script, StringVar, BooleanVar, ObjectVar
from extras.models import Tag
from ipam.models import IPAddress, Prefix
import nmap


class IpScan(Script):
    # optional variables in UI here!
    target_prefix = ObjectVar(
        label='Target Prefix',
        description='The CIDR prefix you would like to scan for hostnames',
        model=Prefix,
        null_option=True,
        required=False,
    )
    create_new = BooleanVar(
        label="Create New Objects",
        default=True,
        description="Whether to create new objects for non-existant NetBox items"
    )
    enabled_filter = BooleanVar(
        label="Tag Based Scanning",
        default=False,
        description="Whether to filter the hosts by the provided Scan Tag",
    )
    scan_recursive = BooleanVar(
        label="Scan Recursively",
        default=False,
        description="This will scan a whole tagged network, and work against each address as if it were tagged",
    )
    scan_tag = ObjectVar(
        label="Tag Filter",
        description="Select the Tag to filter Prefixes to be filtered by",
        model=Tag,
        null_option=True,
        required=False,
    )

    class Meta:
        name = "Subnet Scanner"
        description = "Scans available prefixes and updates ip addresses in IPAM Module"

    def run(self, data, commit):
        target_prefix = data['target_prefix']
        enabled_filter = data['enabled_filter']
        scan_recursive = data['scan_recursive']
        create_new = data['create_new']

        if enabled_filter:
            scan_tag = data['scan_tag']

        def process_prefix(cidr_network):
            # Grab CIDR prefix from provided CIDR range
            prefix = cidr_network.mask_length

            # Instantiate an NMAP scan generator for quicker processing
            nm = nmap.PortScannerYield()

            # Loop through the returned dict
            # The provided '-sL' arguments narrow the scan down to just
            # gathering the hostname data from each host
            for host, response in nm.scan(hosts=str(cidr_network), arguments='-sL'):
                # Store this data for handy use later (ew, that nesting)
                hostname = response['scan'][host]['hostnames'][0]['name']

                cidr = f'{host}/{prefix}'

                try:
                    # Looking for existing objects in NetBox
                    this_address = IPAddress.objects.get(address=cidr)
                    if enabled_filter and (this_address.tags.contains(scan_tag) or scan_recursive):
                        if not hostname and this_address.status not in ['reserved', 'deprecated']:
                            this_address.status = 'deprecated'
                            if commit:
                                self.log_info(
                                    f'{cidr}: No response from existing address, deprecating')
                                this_address.save()
                        elif hostname and this_address.status == 'deprecated':
                            this_address.status = 'active'
                            if commit:
                                self.log_info(
                                    f'{cidr}: Response from deprecated host, reactivating')
                                this_address.save()

                except IPAddress.DoesNotExist:
                    # Only act against hosts that return hostname data
                    if hostname:
                        if create_new:
                            # Only creates a new object if one does not exist
                            new_address = IPAddress(
                                address=cidr,
                                dns_name=hostname,
                                description=f'Automatically pulled by {self.Meta.name}',
                            )
                            if commit:
                                # Evaluates the Commit checkbox on form submission
                                new_address.save()
                                self.log_info(
                                    f'{cidr}: Response from new address, adding')
                        else:
                            self.log_info(
                                f'{cidr}: Response from new address, skipping')

        if target_prefix:
            process_prefix(target_prefix)
        else:
            for prefix in Prefix.objects.filter(tags=scan_tag):
                process_prefix(prefix.prefix)
