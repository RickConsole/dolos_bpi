var dateFormat = require('dateformat')
const fs = require('fs')
const os = require('os'); // Added for network interface IP
const EventEmitter = require('events')
// const config = require('./config.js') // Will be replaced by CLI args + defaults
const fastify = require('fastify')({
  logger: true,
  bodyLimit: 19922944
})

fastify.register(require('fastify-socket.io'), {})

console.log(fs.readFileSync(__dirname + "/banner.txt", "utf8"))

// --- Argument Parsing ---
const args = process.argv.slice(2);
const parsedArgs = {};
for (let i = 0; i < args.length; i++) {
  if (args[i].startsWith('--')) {
    const key = args[i].substring(2);
    const nextArg = args[i+1];
    if (nextArg && !nextArg.startsWith('--')) {
      parsedArgs[key] = nextArg;
      i++; // Skip next arg since it's a value
    } else {
      parsedArgs[key] = true; // For boolean flags
    }
  }
}

const parsedConfig = {
  mgmt_if: parsedArgs.mgmt_if || 'wan', // Default if not provided
  mitm_bridge_name: parsedArgs.mitm_bridge || 'dolos_bridge',
  mitm_switch_if: parsedArgs.mitm_switch_if,
  mitm_supplicant_if: parsedArgs.mitm_supplicant_if,
  attacker_bridge_subnet: parsedArgs.attacker_bridge_subnet,
  mitm_bridge_apipa_ip: parsedArgs.mitm_bridge_apipa_ip, // Will use default in BridgeControllerAdapted if undefined
  mitm_bridge_mac: parsedArgs.mitm_bridge_mac,           // Will use default in BridgeControllerAdapted if undefined
  use_network_manager: parsedArgs.use_network_manager === 'true' || parsedArgs.use_network_manager === true, // Ensure boolean

  // Defaults from original config.js, can be overridden if passed as CLI args too
  ephemeral_ports: parsedArgs.ephemeral_ports || '61000-62000',
  virtual_gateway_ip: parsedArgs.virtual_gateway_ip || '169.254.66.55',
  replace_default_route: parsedArgs.replace_default_route === 'true' || parsedArgs.replace_default_route === true || false,
  run_command_on_success: parsedArgs.run_command_on_success === 'true' || parsedArgs.run_command_on_success === true || false,
  autorun_command: parsedArgs.autorun_command || '',
};

console.log("Parsed Configuration:");
console.log(parsedConfig);

var macs = JSON.parse(fs.readFileSync(__dirname + "/mac_to_vendor.js", "utf8"))

//read keystrokes from cmdline
const readline = require('readline')
readline.emitKeypressEvents(process.stdin)
process.stdin.setRawMode(true)

//custom class to manage the bridge interface, set iptables/ebtables/arptables rules, and update system network info 
const BridgeControllerAdapted = require('./bridge_controller_adapted.js')

var bridge_controller = new BridgeControllerAdapted(parsedConfig)
bridge_controller.start_mitm_operations() // Changed from start_bridge()

process.stdin.on('keypress', (str, key) => {
  if (key.ctrl && key.name === 'c') {
    // Cleanup is now primarily handled by dolos_run.sh trap.
    // This will call cleanup_rules_and_exit(true) which flushes rules and exits Node.
    bridge_controller.flush_tables(true)
  } else if (key.name === 'a') {
    bridge_controller.allow_internet_traffic()
  } else if (key.name === 'd') {
    bridge_controller.send_dhcp_probe()
  } else if (key.name === 'i') {
    console.log("Network Info")
    console.log(JSON.stringify(bridge_controller.net_info.print_info(), null, 4))
    console.log("ARP Table")
    console.log(JSON.stringify(bridge_controller.net_info.arp_table.entries,null, 4))
  }
})

//favicon
fastify.route({
    method: ['GET'],
    url: '/favicon.ico',
    handler: async function (req, reply) {
        let stream = fs.createReadStream(__dirname + "/resources/misc/favicon.ico")
        reply.type('image/x-icon').send(stream)
    }
})

//basic homepage. You can mod it to look like a normal server of your choosing
fastify.route({
    method: ['GET'],
    url: '/',
    handler: async function (req, reply) {
        let stream = fs.createReadStream(__dirname + "/resources/pages/homepage.html")
        reply.type('text/html').send(stream)
    }
})

//static .js files
fastify.route({
    method: ['GET'],
    url: '/static/js/*',
    handler: async function (req, reply) {
        let stream = fs.createReadStream(__dirname + "/resources/js/" + req.params['*'])
        reply.type('text/javascript').send(stream)
    }
})

//static .css files
fastify.route({
    method: ['GET'],
    url: '/static/css/*',
    handler: async function (req, reply) {
        let stream = fs.createReadStream(__dirname + "/resources/styles/" + req.params['*'])
        reply.type('text/css').send(stream)
    }
})

//favicon
fastify.route({
    method: ['GET'],
    url: '/current_log',
    handler: async function (req, reply) {
        let stream = fs.createReadStream(__dirname + "/logs/current.log")
        reply.type('text').send(stream)
    }
})

//overwrite default route to allow Internet traffic from the bridge interface
fastify.route({
    method: ['GET'],
    url: '/allow_internet_traffic',
    handler: async function (req, reply) {
        bridge_controller.allow_internet_traffic()
        reply.send(`Added default route via MitM bridge ${parsedConfig.mitm_bridge_name}`)
    }
})

//force reverse lookup of client hostname
fastify.route({
    method: ['GET'],
    url: '/lookup_hostname',
    handler: async function (req, reply) {
        bridge_controller.net_info.lookup_hostname()
        reply.send('Performing reverse lookup')
    }
})

//force a DHCP Discover message to the network
fastify.route({
    method: ['GET'],
    url: '/send_dhcp_probe',
    handler: async function (req, reply) {
        bridge_controller.send_dhcp_probe()
        reply.send('Performing DHCP Discover')
    }
})

//look up a vendor for a MAC address
fastify.route({
    method: ['GET'],
    url: '/get_vendor',
    handler: async function (req, reply) {
      var mac_addr = req.query['mac_addr']
      while(mac_addr != ""){
        mac_addr = mac_addr.toUpperCase()
        if(macs[mac_addr] != undefined){
          reply.send(macs[mac_addr])
          return
        }else{
          mac_addr = mac_addr.slice(0, mac_addr.length - 1)
        }
      }
      reply.send("unknown")
    }
})

//catch any node exceptions instead of exiting
process.on('uncaughtException', function (err) {
  console.log(dateFormat("isoDateTime") + " " + 'Caught exception: ', err)
})

fastify.ready(function(err){
    if (err) throw err
    fastify.io.on('connect', function(socket){
        console.info('Socket connected!', socket.id)
        bridge_controller.on("bridge_update", function(data) {
            fastify.io.emit("bridge_update", data)
        })
      socket.on('get_update', function(){
        let net_info = bridge_controller.net_info.print_info()
        fastify.io.emit("network_info", net_info)
        let arp_info = bridge_controller.net_info.print_info()
        fastify.io.emit("arp_info", bridge_controller.net_info.arp_table.entries)
      })
    })
})

// Helper function to get IP of an interface
function getInterfaceIp(interfaceName) {
  const nets = os.networkInterfaces();
  const results = {};

  for (const name of Object.keys(nets)) {
    if (name === interfaceName) {
      for (const net of nets[name]) {
        // Skip over non-IPv4 and internal (i.e. 127.0.0.1) addresses
        if (net.family === 'IPv4' && !net.internal) {
          return net.address;
        }
      }
    }
  }
  return '0.0.0.0'; // Default if not found or no IP
}

// Run the server!
const start = async () => {
  const mgmtIpAddress = getInterfaceIp(parsedConfig.mgmt_if);
  fastify.listen(4444, mgmtIpAddress, (err) => {
    if (err) {
      fastify.log.error(err)
      process.exit(1)
    }
    // fastify.log.info(`server listening on ${fastify.server.address().port}`) // This might be null if host is specified
    console.log(`Server listening on ${mgmtIpAddress}:${fastify.server.address().port}`);
  })
}
start()
