# encoding: utf-8

# ------------------------------------------------------------------------------
# Copyright (c) 2015 SUSE LINUX GmbH, Nuernberg, Germany.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact SUSE Linux GmbH.
#
# ------------------------------------------------------------------------------
#
# Summary: The main dialog, showing a list of all connections and allow user to modify their configuration.
# Authors: Howard Guo <hguo@suse.com>

require "yast"
require "cfa/sysctl_config"

Yast.import "Package"
Yast.import "Service"
Yast.import "SuSEFirewall"
Yast.import "Summary"

module Yast
    class IPSecConfModule < Module
        CUSTOMRULES_FILE = "/etc/YaST2/vpn_firewall_rules"
        CUSTOMRULES_BAK_FILE = "/etc/YaST2/.vpn_firewall_rules_backup"
        include Yast::Logger

        # If TCP MSS reduction is required, the new MSS will be this value.
        REDUCED_MSS = 1220

        def initialize
            log.info "IPSecConf is initialised"
            @orig_conf = {}
            @unsupported_conf = []
            @orig_secrets = {}
            @unsupported_secrets = []

            @ipsec_conns = {}
            @ipsec_secrets = {"psk" => [], "rsa" => [], "eap" => [], "xauth" => []}

            @enable_ipsec = false
            @tcp_reduce_mss = false
            @autoyast_modified = false
        end

        def main
            textdomain "vpn"
        end

        # Read system settings, daemon settings, and IPSec configurations.
        def Read
            log.info "IPSecConf.Read is called"
            # Establish the internal representation of IPSec connections and secrets
            load_ipsec_conf_ini
            load_ipsec_secrets_ini
            # Read daemon settings
            @enable_ipsec = Service.Enabled("ipsec")
            customrules_content = get_customrules_txt
            @tcp_reduce_mss = customrules_content != nil && customrules_content.include?("--set-mss #{REDUCED_MSS}")
            @autoyast_modified = true
        end

        # Return raw ipsec.conf deserialised by SCR.
        def GetDeserialisedIPSecConf
            return @orig_conf
        end

        # Return raw ipsec.secrets deserialised by SCR.
        def GetDeserialisedIPSecSecrets
            return @orig_secrets
        end

        # Return all connection configurations.
        def GetIPSecConnections
            return @ipsec_conns
        end

        # Return the section names of unsupported connection configuration.
        def GetUnsupportedConfiguration
            return @unsupported_conf
        end

        # Return IPSec passwords/secrets configuration.
        def GetIPSecSecrets
            return @ipsec_secrets
        end

        # Return the names of unsupported IPSec password/secret types.
        def GetUnsupportedSecrets
            return @unsupported_secrets
        end

        # Return true if IPSec daemon is enabled, otherwise false.
        def DaemonEnabled?
            return @enable_ipsec
        end

        # Return true if TCP MSS reduction workaround is enabled, otherwise false.
        def TCPReduceMSS?
            return @tcp_reduce_mss
        end

        # Create a firewall configuration commands for all VPN gateways. Return the commands array.
        def gen_firewall_commands
            ret = []
            # Find the gateway VPNs offering Internet connectivity, and collect the client's address pool.
            inet_access_networks = @ipsec_conns.select { |name, conf|
                leftsubnet = conf["leftsubnet"]
                leftsubnet != nil && (leftsubnet.include?("::/0") || leftsubnet.include?("0.0.0.0/0"))
            }.map{|name, conf| conf["rightsourceip"]}
            # Open ports for IKE and allow ESP protocol
            dport_accept_template = "%s -A INPUT -p udp --dport %d -j ACCEPT"
            p_accept_template = "%s -A INPUT -p %d -j ACCEPT"
            open_prot = ""
            if @ipsec_conns.length > 0
                ret << dport_accept_template % ["iptables", 500]
                ret << dport_accept_template % ["iptables", 4500]
                ret << dport_accept_template % ["ip6tables", 500]
                ret << dport_accept_template % ["ip6tables", 4500]
                ret << p_accept_template % ["iptables", 50]
                ret << p_accept_template % ["ip6tables", 50]
            end
            # Reduce TCP MSS - if this has to be done, it must come before FORWARD and MASQUERADE
            inet_access = ""
            if @tcp_reduce_mss
                ret <<  "iptables -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss #{REDUCED_MSS+1}:65535 -j TCPMSS --set-mss #{REDUCED_MSS}"
                ret << "ip6tables -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss #{REDUCED_MSS+1}:65535 -j TCPMSS --set-mss #{REDUCED_MSS}"
            end
            # Forwarding for Internet access
            inet_access_networks.each { |cidr|
                iptables = "iptables"
                if cidr.include?(":")
                    iptables = "ip6tables"
                end
                ret << "#{iptables} -A FORWARD -s #{cidr} -j ACCEPT"
                ret << "#{iptables} -A FORWARD -d #{cidr} -j ACCEPT"
                ret << "#{iptables} -t nat -A POSTROUTING -s #{cidr} -j MASQUERADE"
            }
            return ret
        end

        # Apply IPSec configuration.
        def Write
            log.info("IPSecConf.Write is called, connections are: " + @ipsec_conns.keys.to_s)
            successful = true
            # Install packages
            install_pkgs = []
            if !Package.Installed("strongswan-ipsec")
                install_pkgs = ["strongswan-ipsec"]
            end
            if !Package.Installed("strongswan")
                install_pkgs = ["strongswan"]
            end
            if @enable_ipsec && install_pkgs.length > 0
                if !Package.DoInstall(install_pkgs)
                    Report.Error(_("Failed to install IPSec packages."))
                    return false
                end
            end
            # Write configuration files only after having installed packages
            SCR.Write(path(".etc.ipsec_conf.all"), makeIPSecConfINI)
            SCR.Write(path(".etc.ipsec_conf"), nil)
            SCR.Write(path(".etc.ipsec_secrets.all"), makeIPSecSecretsINI)
            SCR.Write(path(".etc.ipsec_secrets"), nil)
            # Enable/disable daemon
            if @enable_ipsec
                Service.Enable("strongswan-starter")
                if !(Service.Active("ipsec") ? Service.Restart("ipsec") : Service.Start("ipsec"))
                    Report.Error(_("Failed to start IPSec daemon."))
                    successful = false
                end
            else
                Service.Stop("ipsec")
                Service.Disable("strongswan-starter")
            end
            # Configure IP forwarding
            sysctlconfig_modified = false
            if @ipsec_conns.any? { |name, conf|
                leftsubnet = conf["leftsubnet"]
                !leftsubnet.nil? && leftsubnet.include?(".")
            }
                sysctlconfig_file.forward_ipv4 = true
                sysctlconfig_file.ipv4_forwarding_all = true
                sysctlconfig_file.ipv4_forwarding_default = true
                sysctlconfig_modified = true
            end
            if @ipsec_conns.any? { |name, conf|
                leftsubnet = conf["leftsubnet"]
                !leftsubnet.nil? && leftsubnet.include?(":")
            }
                sysctlconfig_file.ipv6_forwarding_all = true
                sysctlconfig_file.ipv6_forwarding_default = true
                sysctlconfig_modified = true
            end
            if sysctlconfig_modified
                sysctlconfig_file.save unless sysctlconfig_file.conflict?
                # --system : Load settings from all system configuration files.
                # /boot/sysctl.conf-<kernelversion>
                # /run/sysctl.d/*.conf
                # /etc/sysctl.d/*.conf
                # /usr/local/lib/sysctl.d/*.conf
                # /usr/lib/sysctl.d/*.conf
                # /lib/sysctl.d/*.conf
                # /etc/sysctl.conf
                sysctl_apply = SCR.Execute(Yast::Path.new(".target.bash_output"), "/sbin/sysctl --system 2>&1")
                if !sysctl_apply["exit"].zero?
                    Report.LongError(_("Failed to apply IP forwarding settings using sysctl:") + sysctl_apply["stdout"])
                    successful = false
                end
            end
            # Configure/deconfigure firewall
            uninstall_customrules
            if @enable_ipsec
                install_customrules(gen_firewall_commands)
            end
            SuSEFirewall.Read
            if SuSEFirewall.IsEnabled
                if @enable_ipsec
                    if !SuSEFirewall.IsStarted
                        Report.Warning(_("SuSE firewall is enabled but not activated.\n" +
                            "In order for VPN to function properly, SuSE firewall will now be activated."))
                    end
                    if !SuSEFirewall.SaveAndRestartService
                        Report.Error(_("Failed to restart SuSE firewall."))
                        successful = false
                    end
                else
                    if SuSEFirewall.IsStarted && !SuSEFirewall.SaveAndRestartService
                        Report.Error(_("Failed to restart SuSE firewall."))
                        successful = false
                    end
                end
            else
                Report.LongWarning(
                    _("Both VPN gateway and clients require special SuSE firewall configuration.\n" +
                      "SuSE firewall is not enabled, therefore you must manually run the configuration script " +
                      "on every reboot. The script will be run now.\n" +
                      "The script is located at %s") % [CUSTOMRULES_FILE])
            end
            @autoyast_modified = false
            return successful
        end

        # Import all daemon settings and configuration (used by both AutoYast and UI).
        def Import(params)
            log.info("IPSecConf.Import is called with parameter: " + params.to_s)
            if !params
                return false
            end
            @enable_ipsec = !!params["enable_ipsec"]
            @tcp_reduce_mss = !!params["tcp_reduce_mss"]
            @ipsec_conns = params.fetch("ipsec_conns", {})
            @ipsec_secrets = params.fetch("ipsec_secrets", {})
            @autoyast_modified = true
            return true
        end

        # AutoYaST: Export all daemon settings and configuration.
        def Export
            log.info("IPSecConf.Export is called, connections are: " + @ipsec_conns.keys.to_s)
            return {
                "enable_ipsec" => @enable_ipsec,
                "tcp_reduce_mss" => @tcp_reduce_mss,
                "ipsec_conns" => @ipsec_conns,
                "ipsec_secrets" => @ipsec_secrets
            }
        end

        # AutoYaST: Return a rich text summary of the current configuration.
        def Summary
            log.info("IPSecConf.Summary is called")
            ret = Summary.AddHeader("", _("VPN Global Settings"))
            ret = Summary.AddLine(ret, _("Enable VPN (IPSec) daemon: %s") % [(!!@enable_ipsec).to_s])
            ret = Summary.AddLine(ret, _("Reduce TCP MSS: %s") % [(!!@tcp_reduce_mss).to_s])
            ret = Summary.AddHeader(ret, _("Gateway and Connections"))
            if @ipsec_conns != nil
                @ipsec_conns.each{|name, conf|
                    if conf["right"] == "%any"
                        # Gateway summary
                        ret = Summary.AddLine(ret, name + ": " +
                                _("A gateway serving clients in ") + conf["rightsourceip"].to_s)
                    else
                        # Client summary
                        ret = Summary.AddLine(ret, name + ": " +
                                _("A client connecting to ") + conf["right"])
                    end
                }
            end
            return ret
        end

        # AutoYaST: Set modified flag to true. Really does nothing to the logic.
        def SetModified
            log.info("IPSecConf.SetModified is called")
            @autoyast_modified = true
        end

        # AutoYaST: Get the modified flag.
        def GetModified
            log.info("IPSecConf.GetModified is called, modified flag is: " + @autoyast_modified.to_s)
            return @autoyast_modified
        end

        # AutoYaST: Clear all connections and secrets, and reset all flags.
        def Reset
            log.info("IPSecConf.Reset is called")
            @orig_conf = {}
            @unsupported_conf = []
            @orig_secrets = {}
            @unsupported_secrets = []

            @ipsec_conns = {}
            @ipsec_secrets = {"psk" => [], "rsa" => [], "eap" => [], "xauth" => []}

            @enable_ipsec = false
            @tcp_reduce_mss = false
            @autoyast_modified = false
        end

        publish :function => :Read, :type => "void ()"
        publish :function => :Write, :type => "boolean ()"
        publish :function => :Import, :type => "boolean (map)"
        publish :function => :Export, :type => "map ()"
        publish :function => :Summary, :type => "string ()"
        publish :function => :SetModified, :type => "void ()"
        publish :function => :GetModified, :type => "boolean ()"

        # Load ipsec.conf from INI agent.
        def load_ipsec_conf_ini
            @orig_conf = SCR.Read(path(".etc.ipsec_conf.all"))
            # Establish the internal representation of IPSec connection configuration
            @ipsec_conns = {}
            @unsupported_conf = []
            @orig_conf["value"].each { |kv|
                sect_type, sect_name = kv["name"].strip.split(/\s+/, 2)
                params = kv["value"]
                if sect_type == "conn" && sect_name != "%default"
                    @ipsec_conns[sect_name] = Hash[
                        params.map { |paramkv| [paramkv["name"].strip, paramkv["value"].strip] }
                    ]
                else
                    # CA, config-setup, and %default configurations are not supported
                    @unsupported_conf += [kv["name"].strip]
                end
            }
            log.info "Loaded IPSec configuration: " + @ipsec_conns.keys.to_s
            log.info "Unsupported configuration: " + @unsupported_conf.to_s
        end

        # Load ipsec.secrets from INI agent.
        def load_ipsec_secrets_ini
            @ipsec_secrets = {"psk" => [], "rsa" => [], "eap" => [], "xauth" => []}
            log_no_secrets = []
            @unsupported_secrets = []
            @orig_secrets = SCR.Read(path(".etc.ipsec_secrets.all"))
            @orig_secrets["value"].each { |kv|
                left_side = kv["name"].strip
                key_type, key_content = kv["value"].strip.split(/\s+/, 2)
                if @ipsec_secrets.has_key?(key_type.downcase)
                    key_type = key_type.strip.downcase
                    key_content = key_content.strip.delete '"'
                    @ipsec_secrets[key_type] += [{"id" => left_side, "secret" => key_content}]
                    log_no_secrets += [(left_side + " " + key_type).strip]
                else
                    @unsupported_secrets += [(left_side + ' ' + key_type).strip]
                end
            }
            log.info "Loaded IPSec keys and secrets: " + log_no_secrets.to_s
            log.info "Unsupported secrets " + @unsupported_secrets.to_s
        end

        def mkININode(kind, name, value, root = false)
            return {
                "comment" => "",
                "kind" => root ? "section" : kind,
                "type" => root ? -1 : 0,
                "name" => name == nil ? "" : name,
                "value" => value == nil ? [] : value
            }.merge(root || kind == "section" ? {"file" => -1} : {})
        end

        # Make INI nodes from IPSec parameters, for INI agent. Each connection is a section.
        def makeIPSecConfINI
            mkININode(nil, nil,
                @ipsec_conns.map { | name, params |
                    mkININode("section", "conn " + name, params.map { | pk, pv|
                        mkININode("value", pk, pv, false)
                    }, false)
                }, true)
        end

        # Make INI nodes from IPSec secrets, for INI agent. There are no sections.
        def makeIPSecSecretsINI
            mkININode(nil, nil,
                @ipsec_secrets.map { | keytype, idAndSecret |
                    idAndSecret.map { | entry|
                        mkININode(
                            "value",
                            entry["id"],
                            "%s %s" % [keytype.upcase, keytype.upcase == "RSA" ? entry["secret"] : '"' + entry["secret"] + '"'],
                            false
                        )
                    }
                }.flatten, true)
        end

        # Return the latest file name of custom-rules script in firewall.
        # If the file does not exist or not specified, return nil.
        def get_susefw_customrules
            attr_value = SCR.Read(path(".sysconfig.SuSEfirewall2.FW_CUSTOMRULES")).to_s.strip
            if attr_value == ''
                return nil
            end
            if !::File.exist?(attr_value)
                return nil
            end
            return attr_value
        end

        # Read the latest content of custom rules script defined in firewall.
        # Return nil if no such script is being used.
        def get_customrules_txt
            filename = get_susefw_customrules
            if filename == nil
                return nil
            end
            return IO.readlines(filename).join('')
        end

        # Return true only if the
        def customrules_contain_all(existing_txt, cmds)
            new_txt = merge_into_customrules(existing_txt, cmds)
            return new_txt.strip == existing_txt.strip
        end

        # Merge the firewall commands into the specified section of custom rules text and return the whole text.
        def merge_into_customrules_section(existing_txt, cmds, section)
            # Split text into lines, because each iptable command occupies exactly one line.
            lines = existing_txt.split("\n")
            # Find the line number of the section for new iptable commands to be placed
            lineno_chain = -1
            lines.each_with_index {|line, lineno|
                if line.match(section) != nil
                    lineno_chain = lineno
                    break
                end
            }
            # Figure out new commands to merge
            insert_cmds = []
            cmds.each { |cmd|
                cmd = cmd.strip
                if lines.none?{|line| line.index(cmd) != nil}
                    insert_cmds << cmd
                end
            }
            # Put new commands into the lines immediately following the section declaration
            if insert_cmds.length > 0
                lines.insert(lineno_chain+1, *insert_cmds)
            end
            return lines.join("\n")
        end

        # Merge the firewall commands into appropriate sections of the custom rules text and return the whole text.
        def merge_into_customrules(existing_txt, cmds)
            # Categorise the firewall commands
            open_port = []
            forward_route = []
            cmds.each {|cmd|
                # Open port/allow protocol commands are in -A INPUT, i.e. "chian_creation".
                if cmd.index('-A INPUT') != nil
                    open_port << cmd
                else
                    # All other commands deal with changing MSS or enable NAT, they go into "befor_masq".
                    forward_route << cmd
                end
            }
            txt = merge_into_customrules_section(existing_txt, open_port, /fw_custom_after_chain_creation.*{/)
            return merge_into_customrules_section(txt, forward_route, /fw_custom_before_masq.*{/) + "\n"
        end

        # Remove some iptable commands from custom rules text. Return the new text.
        def remove_from_customrules(existing_txt, cmds)
            # Split text into lines, because each iptable command occupies exactly one line.
            lines = existing_txt.split("\n")
            ret = []
            lines.each {|line|
                if cmds.none?{|cmd| line.index(cmd.strip) != nil}
                    ret << line
                end
            }
            return ret.join("\n") + "\n"
        end

        # If firewall does not yet use a custom rules script, create it and give it to firewall.
        # Then no matter what, merge the firewall commands into the effective custom rules script.
        def install_customrules(cmds)
            template = '
#/bin/bash
fw_custom_after_chain_creation() {
true
}
fw_custom_after_chain_creation
fw_custom_before_port_handling() {
true
}
fw_custom_before_port_handling
fw_custom_before_masq() {
true
}
fw_custom_before_masq
fw_custom_before_denyall() {
true
}
fw_custom_before_denyall
fw_custom_after_finished() {
true
}
fw_custom_after_finished
'
            # Always save a copy to the default location so that user can run it manually
            IO.write(CUSTOMRULES_FILE, merge_into_customrules(template, cmds))
            customrules_file = get_susefw_customrules()
            if customrules_file == nil
                # If user is not already using custom rules script, set custom rules script to the default location.
                new_file = CUSTOMRULES_FILE + '.applied'
                IO.write(new_file, merge_into_customrules(template, cmds))
                SCR.Write(path(".sysconfig.SuSEfirewall2.FW_CUSTOMRULES"), new_file)
                SCR.Write(path(".sysconfig.SuSEfirewall2"), nil)
            else
                # Merge commands into the existing custom rules script.
                file_name = get_susefw_customrules
                txt = merge_into_customrules(get_customrules_txt, cmds)
                IO.write(customrules_file, txt)
            end
            # Keep a copy of the applied firewall commands so they may be reverted later on
            IO.write(CUSTOMRULES_BAK_FILE, cmds.join("\n"))
        end

        def uninstall_customrules
            file_name = get_susefw_customrules
            if file_name == nil
                return
            end
            # Remove firewall commands from the file
            IO.write(file_name, remove_from_customrules(IO.read(file_name), IO.readlines(CUSTOMRULES_BAK_FILE)))
        end

        # Returns the sysctl configuration
        #
        # @note It memoizes the value until {#main} is called.
        #
        # @return [Yast2::CFA::SysctlConfig]
        def sysctlconfig_file
          return @sysctlconfig_file if @sysctlconfig_file
          @sysctlconfig_file = CFA::SysctlConfig.new
          @sysctlconfig_file.load
          @sysctlconfig_file
        end
    end
    IPSecConf = IPSecConfModule.new
    IPSecConf.main
end
