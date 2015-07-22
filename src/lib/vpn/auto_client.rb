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
# Summary: Implementation of the AutoYaST interface of YaST VPN module.
# Authors: Howard Guo <hguo@suse.com>

require "installation/auto_client"
require "vpn/main_dialog"
Yast.import "IPSecConf"

module Yast
    # The AutoYast interface for VPN module.
    class VPNAutoClient < ::Installation::AutoClient
        def initialize
            textdomain "vpn"
        end

        def run
            progress_orig = Progress.set(false)
            ret = super
            Progress.set(progress_orig)
            ret
        end

        # Import configuration parameters saved by Export operation.
        def import(data)
            return IPSecConf.Import(data)
        end

        # Return a hash of configuration parameters, later to be Imported and applied.
        def export
            return IPSecConf.Export
        end

        def modified?
            return IPSecConf.GetModified
        end

        def modified
            IPSecConf.SetModified
        end

        # Return rich text summary for all VPN gateways and connections.
        def summary
            return IPSecConf.Summary
        end

        # Bring up the main dialog to let user work on the configuration.
        def change
            # Reload from SCR agents, but do not reload SCR itself!
            VPN::IPSec.reload
            # Tell main dialog not to immediately apply the configuration
            ret = VPN::MainDialog.new(can_apply: false).run
            if ret == :finish
                IPSecConf.SetModified
            end
            return ret
        end

        # Apply the IPSec configuration.
        def write
            return IPSecConf.Write
        end

        # Load IPSec configuration from this system.
        def read
            return IPSecConf.Read
        end

        # Return list of packages required for VPN to run.
        def pacakges
            return {"install" => ["strongswan", "strongswan-ipsec"], "remove" => []}
        end

        # Reset all configuration flags and clear all VPN connections/secrets.
        def reset
            IPSecConf.Reset
        end
    end
end