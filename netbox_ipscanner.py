import pynetbox, urllib3, networkscan, socket, ipaddress
from extras.scripts import Script

TOKEN='xxx'
NETBOXURL='https://netbox.eample.com'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #disable safety warnings

class IpScan(Script):
    #optional variables in UI here!
    TagBasedScanning = BooleanVar(
        label="Tag Based Scanning?",
        default=False,
        description="enable Tag Based Scanning, to scan only Subnets with specified Tag.",
    )
    tag = StringVar(
         max_length=20,
         label="Scan Tag?",
         default="scan",
         description="specify the Tag to filter Subnets to be scanned",
         required=True,
    )


    class Meta:
        name = "IP Scanner"
        description = "Scans available prefixes and updates ip addresses in IPAM Module"

 
    def run(self, data, commit):

        def reverse_lookup(ip):
            '''
            Mini function that does DNS reverse lookup with controlled failure
            '''
            try:
                data = socket.gethostbyaddr(ip)
            except Exception:
                return '' #fails gracefully
            if data[0] == '': #if there is no name
                return ''
            else:
                return data[0]

        nb = pynetbox.api(NETBOXURL, token=TOKEN)
        nb.http_session.verify = False #disable certificate checking

        subnets = nb.ipam.prefixes.all() #extracts all prefixes, in format x.x.x.x/yy

        for subnet in subnets:
            if data['TagBasedScanning'] and data['tag'] not in str(subnet.tags): # Only scan subnets with the Tag
                self.log_debug(f'checking {subnet}...Tag is {subnet.tags}')
                self.log_warning(f"Scan of {subnet.prefix} NOT done (missing '{data['tag']}' tag)")
                continue
            if str(subnet.status) == 'Reserved': #Do not scan reserved subnets
                self.log_warning(f"Scan of {subnet.prefix} NOT done (is Reserved)")
                continue
            self.log_debug(f'checking {subnet}...Tag is {subnet.tags}')
            IPv4network = ipaddress.IPv4Network(subnet)
            mask = '/'+str(IPv4network.prefixlen)
            scan = networkscan.Networkscan(subnet)
            scan.run()
            self.log_info(f'Scan of {subnet} done.')
	    
            #Routine to mark as DEPRECATED each Netbox entry that does not respond to ping
            for address in IPv4network.hosts(): #for each address of the prefix x.x.x.x/yy...
		        #self.log_debug(f'checking {address}...')
                netbox_address = nb.ipam.ip_addresses.get(address=address) #extract address info from Netbox
                if netbox_address != None: #if the ip exists in netbox // if none exists, leave it to discover
                    if str(netbox_address).rpartition('/')[0] in scan.list_of_hosts_found: #if he is in the list of "alive"
                        pass #do nothing: It exists in NB and is in the pinged list: ok continue, you will see it later when you cycle the ip addresses that have responded whether to update something
			            #self.log_success(f"The host {str(netbox_address).rpartition('/')[0]} exists in netbox and has been pinged")
                    else: #if it exists in netbox but is NOT in the list, mark it as deprecated
                        if str(netbox_address.status) == 'Deprecated' or str(netbox_address.status) == 'Reserved': #check the ip address to be Deprecated or Reserved
                            pass # leave it as is
                        else:
                            self.log_warning(f"Host {str(netbox_address)} exists in netbox but not responding --> DEPRECATED")
                            nb.ipam.ip_addresses.update([{'id':netbox_address.id, 'status':'deprecated'},])
            ####

            if scan.list_of_hosts_found == []:
                self.log_warning(f'No host found in network {subnet}')
            else:
                self.log_success(f'IPs found: {scan.list_of_hosts_found}')
            for address1 in scan.list_of_hosts_found: #for each ip in the ping list...
                ip_mask=str(address1)+mask
                current_in_netbox = nb.ipam.ip_addresses.get(address=ip_mask) #extract current data in Netbox related to ip
                #self.log_debug(f'pinged ip: {address1} mask: {mask} --> {ip_mask} // extracted ip from netbox: {current_in_netbox}')
                if current_in_netbox != None: #the pinged address is already present in the Netbox, mark it as Active and check the name if it has changed
                    nb.ipam.ip_addresses.update([{'id':current_in_netbox.id, 'status':'active'},])
                    name = reverse_lookup(address1) #name resolution from DNS
                    if current_in_netbox.dns_name == name: #the names in Netbox and DNS match, do nothing
                        pass
                    else: #the names in Netbox and in DNS *DO NOT* match --> update Netbox with DNS name
                        self.log_success(f'Name for {address1} updated to {name}')
                        nb.ipam.ip_addresses.update([{'id':current_in_netbox.id, 'dns_name':name},])
                else: #the pinged address is NOT present in Netbox, I have to add it
                    name = reverse_lookup(address1) #name resolution from DNS
                    res = nb.ipam.ip_addresses.create(address=ip_mask, status='active', dns_name=name)
                    if res:
                        self.log_success(f'Added {address1} - {name}')
                    else:
                        self.log_error(f'Adding {address1} - {name} FAILED')
						