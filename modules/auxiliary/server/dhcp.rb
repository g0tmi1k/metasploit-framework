##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DHCPServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'DHCP Server',
      'Description' => %q{
        This module provides a DHCP service
      },
      'Author' => [ 'scriptjunkie', 'apconole@yahoo.com' ],
      'License' => MSF_LICENSE,
      'Actions' => [
        [ 'Service', 'Description' => 'Run DHCP server' ]
      ],
      'PassiveActions' => [
        'Service'
      ],
      'DefaultAction' => 'Service'
    )
  end

  def run
    print_status("Starting DHCP server...")
    @dhcp = Rex::Proto::DHCP::Server.new(datastore)
    @dhcp.report do |event|
      case event[:type]
      when :dhcp_discover
        vprint_status("DHCPDISCOVER from #{event[:mac]}")
      when :dhcp_request
        vprint_good("DHCPREQUEST #{event[:mac]} -> #{event[:ip]}")
        report_host(
          :host => event[:ip],
          :mac => event[:mac],
          :comments => 'Added from DHCP: auxiliary/server/dhcp'
        )
      end
    end
    @dhcp.start
    add_socket(@dhcp.sock)

    # Wait for finish..
    while @dhcp.thread.alive?
      sleep 2

    end

    print_status("Stopping DHCP server...")
    @dhcp.stop
  end
end
