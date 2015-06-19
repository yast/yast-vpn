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
Yast.import "UI"
Yast.import "Icon"
Yast.import "Label"
Yast.import "Popup"

module VPN
    # Ask for a new username and password combination and return them.
    class NewUserDialog
        include Yast::UIShortcuts
        include Yast::I18n
        include Yast::Logger

        def initialize
            textdomain "vpn"
        end

        # Return a tuple of username and password, or :nil if cancelled.
        def run
            render_all
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
                        Left(MinWidth(12, InputField(Id(:username), "Username:", ""))),
                        Left(MinWidth(12, InputField(Id(:password), "Password:", ""))),
                        ButtonBox(
                            PushButton(Id(:ok), Yast::Label.OKButton),
                            PushButton(Id(:cancel), Yast::Label.CancelButton)
                        )
                    )
                )
            end

            def ui_event_loop
                loop do
                    case Yast::UI.UserInput
                    when :ok
                        username = Yast::UI.QueryWidget(Id(:username), :Value)
                        password = Yast::UI.QueryWidget(Id(:password), :Value)
                        # Trailing/leading spaces are not allowed in username
                        username = username == nil ? "" : username.strip
                        # They are however allowed in password
                        password = password == nil ? "" : password
                        if username == "" || password == ""
                            Yast::Popup.Error(_("Please enter both username and password."))
                            redo
                        end
                        if (username =~ /^[A-Za-z0-9_-]+$/) == nil
                            Yast::Popup.Error(_("Please refrain from using special characters and spaces in the username.\n" +
                                                "Acceptable characters are: A-Z, a-z, 0-9, dash, underscore"))
                            redo
                        end
                        return [username, password]
                    else
                        return
                    end
                end
            end
    end
end
