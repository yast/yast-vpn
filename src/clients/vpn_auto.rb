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
# Summary: Run the AutoYaST interface of YaST VPN module.
# Authors: Howard Guo <hguo@suse.com>
require "yast"
require "vpn/main_dialog"
Yast.import "IPSecConf"

module Yast
    # The AutoYast interface for VPN module.
    class VPNAutoClient < Client
        def main
            textdomain "vpn"

            Builtins.y2milestone("---------------------------------")
            Builtins.y2milestone("AutoYast VPN started")
            @ret = nil
            @func = ""
            @param = []

            if Ops.greater_than(Builtins.size(WFM.Args), 0) &&
                Ops.is_string?(WFM.Args(0))
                @func = Convert.to_string(WFM.Args(0))

                if Ops.greater_than(Builtins.size(WFM.Args), 1)
                    arg1 = WFM.Args(1)
                    if Ops.is_list?(arg1)
                        @param = Conver.to_list(arg1)
                    elsif Ops.is_map?(arg1)
                        @param = Convert.to_map(arg1)
                    end
                end
            end

            @func = deep_copy(@func)
            @param = deep_copy(@param)

            Builtins.y2milestone("Args: " + WFM.Args.to_s)
            Builtins.y2milestone("Func: " + @func.to_s)
            Builtins.y2milestone("Param: " + @param.to_s)

            case @func
            when "Read"
                # Read VPN configuration from this system.
                @ret = IPSecConf.Read
            when "Import"
                # Import configuration parameters saved by Export operation.
                @ret = IPSecConf.Import(@param)
            when "Export"
                # Return a hash of configuration parameters, later to be Imported and applied.
                @ret = IPSecConf.Export
            when "Summary"
                # Return rich text summary for all VPN gateways and connections.
                @ret = IPSecConf.Summary
            when "Change"
                # Bring up the main dialog and tell it not to change system configuration
                # Reload from SCR agents, do not reload SCR itself!
                VPN::IPSec.reload
                # Return :finish on save (AutoYast magic), or :abort on abort
                @ret = VPN::MainDialog.new(false).run
                if @ret == :finish
                    IPSecConf.SetModified
                end
            when "Reset"
                # Reset all configuration flags and clear all connections/secrets.
                IPSecConf.Reset
            when "SetModified"
                # Only meaningful to AutoYast, not meaningful to this module.
                IPSecConf.SetModified
            when "GetModified"
                @ret = IPSecConf.GetModified
            when "Write"
                # Apply configuration.
                @ret = IPSecConf.Write
            when "Packages"
                # Return list of packages required for VPN to run.
                @ret = {"install" => ["strongswan", "strongswan-ipsec"], "remove" => []}
            else
                Builtins.y2warning("Func %1: not implemented", @func)
            end

            Builtins.y2milestone("AutoYast VPN finished")
            Builtins.y2milestone("Return value is: " + @ret.to_s)
            Builtins.y2milestone("---------------------------------")
            return deep_copy(@ret)
        end
    end
end

Yast::VPNAutoClient.new.main