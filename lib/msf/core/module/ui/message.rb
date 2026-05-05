# Methods for print messages with status indicators
module Msf::Module::UI::Message
  autoload :Verbose, 'msf/core/module/ui/message/verbose'

  include Msf::Module::UI::Message::Verbose

  def print_error(msg='', prefix: nil)
    msg_prefix = prefix.nil? ? print_prefix : prefix
    super(prefix_message(msg_prefix, msg))
  end

  alias_method :print_bad, :print_error

  def print_good(msg='', prefix: nil)
    msg_prefix = prefix.nil? ? print_prefix : prefix
    super(prefix_message(msg_prefix, msg))
  end

  def print_prefix
    prefix = ''
    if datastore['TimestampOutput'] ||
        (framework && framework.datastore['TimestampOutput'])
      prefix << "[#{Time.now.strftime("%Y.%m.%d-%H:%M:%S")}] "

      xn ||= datastore['ExploitNumber']
      xn ||= framework.datastore['ExploitNumber']
      if xn.is_a?(Integer)
        prefix << "[%04d] " % xn
      end
    end

    if (module_name_output = (datastore['ModuleNameOutput'] ||
        (framework && framework.datastore['ModuleNameOutput'])))
      prefix << "[#{module_name_output}] "
    end
    prefix
  end

  def print_status(msg='', prefix: nil)
    msg_prefix = prefix.nil? ? print_prefix : prefix
    super(prefix_message(msg_prefix, msg))
  end

  def print_warning(msg='', prefix: nil)
    msg_prefix = prefix.nil? ? print_prefix : prefix
    super(prefix_message(msg_prefix, msg))
  end

  private

  # Prepends msg_prefix to msg. If msg already opens with the same peer address
  # that msg_prefix contains (e.g. injected by Msf::Exploit::Remote::Tcp), that
  # leading "ip:port - " is replaced by msg_prefix so the address appears only once.
  def prefix_message(msg_prefix, msg)
    str = msg.to_s
    # IPv4 address (e.g. 127.0.0.1:port)
    if (m = msg_prefix.match(/(\d+\.\d+\.\d+\.\d+:\d+)/))
      pat = /\A#{Regexp.escape(m[1])}\s*-\s*/
    # IPv6 address (e.g. [::1]:port or ::1:port)
    elsif (m = msg_prefix.match(/\[([\da-fA-F:]+)\]:(\d+)/))
      pat = /\A(?:\[#{Regexp.escape(m[1])}\]|#{Regexp.escape(m[1])}):#{m[2]}\s*-\s*/
    else
      return msg_prefix + str
    end

    str.match?(pat) ? str.sub(pat) { msg_prefix } : msg_prefix + str
  end
end
