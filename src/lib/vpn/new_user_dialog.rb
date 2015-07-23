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
# Summary: Display a dialog asking for a new username and password combination.
# Authors: Howard Guo <hguo@suse.com>

require "yast"
require "ui/dialog"
Yast.import "UI"
Yast.import "Label"
Yast.import "Popup"

module VPN
    # Ask for a new username and password combination and return them.
    class NewUserDialog < UI::Dialog
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
                Left(MinWidth(12, InputField(Id(:username), "Username:", ""))),
                Left(MinWidth(12, InputField(Id(:password), "Password:", ""))),
                ButtonBox(
                    PushButton(Id(:ok), Yast::Label.OKButton),
                    PushButton(Id(:cancel), Yast::Label.CancelButton)
                )
            )
        end

        # Return tuple of username/password.
        def ok_handler
            username = Yast::UI.QueryWidget(Id(:username), :Value)
            password = Yast::UI.QueryWidget(Id(:password), :Value)
            # Trailing/leading spaces are not allowed in username
            username.strip! if username
            # They are however allowed in password
            password ||= ""
            if username == "" || password == ""
                Yast::Popup.Error(_("Please enter both username and password."))
                return
            end
            if (username =~ /^[A-Za-z0-9_-]+$/) == nil
                Yast::Popup.Error(_("Please refrain from using special characters and spaces in the username.\n" +
                                    "Acceptable characters are: A-Z, a-z, 0-9, dash, underscore"))
                return
            end
            finish_dialog([username, password])
        end
    end
end
