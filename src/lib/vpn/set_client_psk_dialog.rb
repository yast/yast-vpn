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
Yast.import "UI"
Yast.import "Icon"
Yast.import "Label"
Yast.import "Popup"

module VPN
    # Ask for a PSK (password) for a VPN client.
    class SetClientPSKDialog
        include Yast::UIShortcuts
        include Yast::I18n
        include Yast::Logger

        def initialize
            textdomain "vpn"
        end

        # Return a password string, or :nil if cancelled.
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
                        Left(MinWidth(30, InputField(Id(:password), "Password:", ""))),
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
                        password = Yast::UI.QueryWidget(Id(:password), :Value)
                        password = password == nil ? "" : password
                        if password == ""
                            Yast::Popup.Error(_("Please enter a password."))
                            redo
                        end
                        return password
                    else
                        return
                    end
                end
            end
    end
end
