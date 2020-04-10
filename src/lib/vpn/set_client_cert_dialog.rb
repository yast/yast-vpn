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
# Summary: Display a dialog asking for a new certificate/key combination for a VPN client.
# Authors: Howard Guo <hguo@suse.com>

require "yast"
require "ui/dialog"
Yast.import "UI"
Yast.import "Label"
Yast.import "Popup"

module VPN
    # Ask for a new certificate/key combination for a VPN client
    class SetClientCertDialog < UI::Dialog
        include Yast::UIShortcuts
        include Yast::I18n
        include Yast::Logger

        def initialize(cert_path, key_path)
            super()
            textdomain "vpn"
            @cert_path = cert_path
            @key_path = key_path
        end

        def dialog_options
            Opt(:decorated)
        end

        def dialog_content
            VBox(
                Left(MinWidth(30, HBox(
                        InputField(Id(:cert), _("Path to certificate file:"), @cert_path),
                        Bottom(PushButton(Id(:select_cert), _("Pick..")))))),
                Left(MinWidth(30, HBox(
                        InputField(Id(:cert_key), _("Path to certificate key file:"), @key_path),
                        Bottom(PushButton(Id(:select_cert_key), _("Pick..")))))),
                Left(Label(_("Please do not store the key in the certificate file itself."))),
                ButtonBox(
                    PushButton(Id(:ok), Yast::Label.OKButton),
                    PushButton(Id(:cancel), Yast::Label.CancelButton)
                )
            )
        end

        # Event handlers
        def select_cert_handler
            path = Yast::UI.AskForExistingFile("/", "", _("Pick a PEM encoded certificate file"))
            Yast::UI.ChangeWidget(Id(:cert), :Value, path) unless path.nil?
        end

        def select_cert_key_handler
            path = Yast::UI.AskForExistingFile("/", "", _("Pick a PEM encoded certificate key file"))
            Yast::UI.ChangeWidget(Id(:cert_key), :Value, path) unless path.nil?
        end

        # Return tuple of certificate and certificate key locations.
        def ok_handler
            cert = Yast::UI.QueryWidget(Id(:cert), :Value)
            cert_key = Yast::UI.QueryWidget(Id(:cert_key), :Value)
            cert = cert == nil ? "" : cert.strip
            cert_key = cert_key == nil ? "" : cert_key
            if cert_key == "" || cert_key == ""
                Yast::Popup.Error(_("Please enter both certificate file and key file."))
                return
            end
            finish_dialog([cert, cert_key])
        end

    end
end
