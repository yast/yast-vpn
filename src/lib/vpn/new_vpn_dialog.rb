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
# Summary: Prompt user to enter a name for a new VPN and create the connection.
# Authors: Howard Guo <hguo@suse.com>

require "yast"
Yast.import "UI"
Yast.import "Icon"
Yast.import "Label"
Yast.import "Popup"

module VPN
    # Create a new VPN connection - by default it is a site-to-site gateway.
    class NewVPNDialog
        include Yast::UIShortcuts
        include Yast::I18n
        include Yast::Logger

        def initialize
            textdomain "vpn"
        end

        # Return :ok if new VPN connection is created, otherwise :cancel.
        def run
            return if !render_all
            begin
                return ui_event_loop
            ensure
                Yast::UI.CloseDialog()
            end
        end

        private
            def render_all
                Yast::UI.OpenDialog(
                    Opt(:decorated),
                    VBox(
                        MinWidth(12, InputField(Id(:name), _("Please enter a name for the new VPN connection"), "")),
                        ButtonBox(
                            PushButton(Id(:ok), Yast::Label.OKButton),
                            PushButton(Id(:cancel), Yast::Label.CancelButton)
                        )
                    )
                )
            end
            
        # Return :ok if new VPN connection is created, otherwise :cancel.
            def ui_event_loop
                loop do
                    case Yast::UI.UserInput
                    when :ok
                        name = Yast::UI.QueryWidget(Id(:name), :Value).strip
                        if name == ""
                            Yast::Popup.Error(_("Please enter a VPN connection name."))
                            redo
                        end
                        if (name =~ /^[A-Za-z_-]+[A-Za-z0-9_-]*$/) == nil
                            Yast::Popup.Error(_("Please refrain from using special characters and spaces in the name.\n" +
                                                "Acceptable characters are: A-Z, a-z, 0-9, dash, underscore\n" +
                                                "Name has to begin with a letter."))
                            redo
                        end
                        # Create new connection as a gateway
                        # User will be able to change it to client on main dialog
                        if IPSec.create_conn(name, :client)
                            IPSec.switch_conn(name)
                            return :ok
                        else
                            redo
                        end
                    else
                        return
                    end
                end
            end
    end
end
