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
# Summary: Display a dialog asking for a PSK (password) for a VPN client.
# Authors: Howard Guo <hguo@suse.com>

require "yast"
require "ui/dialog"
Yast.import "UI"
Yast.import "Label"
Yast.import "Popup"

module VPN
    # Ask for a PSK (password) for a VPN client.
    class SetClientPSKDialog < UI::Dialog
        include Yast::UIShortcuts
        include Yast::I18n
        include Yast::Logger

        def initialize
            super
            textdomain "vpn"
        end

        def dialog_options
            Opt(:decorated)
        end

        def dialog_content
            VBox(
                Left(MinWidth(30, InputField(Id(:password), "Password:", ""))),
                ButtonBox(
                    PushButton(Id(:ok), Yast::Label.OKButton),
                    PushButton(Id(:cancel), Yast::Label.CancelButton)
                )
            )
        end

        # Return password string.
        def ok_handler
            password = Yast::UI.QueryWidget(Id(:password), :Value)
            password = password == nil ? "" : password
            if password == ""
                Yast::Popup.Error(_("Please enter a password."))
                return
            end
            finish_dialog(password)
        end
    end
end
