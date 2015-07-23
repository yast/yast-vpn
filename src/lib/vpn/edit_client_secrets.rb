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
# Summary: Display a dialog for managing VPN client secrets.
# Authors: Howard Guo <hguo@suse.com>

require "yast"
require "ui/dialog"
require "vpn/set_client_cert_dialog"
require "vpn/set_client_psk_dialog"
Yast.import "UI"
Yast.import "Label"
Yast.import "Popup"

module VPN
    # Manage VPN client secrets.
    class EditClientSecretsDialog < UI::Dialog
        include Yast::UIShortcuts
        include Yast::I18n
        include Yast::Logger

        def initialize
            super
            textdomain "vpn"

            @require_psk = false
            @require_cert = false
            case IPSec.get_current_conn["scenario"]
            when :client_psk
                @require_psk = true
            when :client_cert
                @require_cert = true
            end
        end

        def dialog_options
            Opt(:decorated)
        end

        def dialog_content
            psk_frame = Frame(_("Pre-shared key for gateways"), VBox(
                                MinSize(40, 8, Table(Id(:psk_table), Header(_("Gateway IP"), _("Pre-shared key"), []))),
                            HBox(
                                PushButton(Id(:psk_set), _("Set")),
                                CheckBox(Id(:psk_show_pwd), Opt(:notify), _("Show key")))))
            cert_frame = Frame(_("Certificate/key pair for gateways"), VBox(
                            MinSize(40, 8, Table(Id(:cert_table), Header(_("Gateway IP"), _("Certificate"), _("Key"), []))),
                            PushButton(Id(:cert_set), _("Set"))))

            display_frame = nil
            if @require_psk
                display_frame = psk_frame
            elsif @require_cert
                display_frame = cert_frame
            else
                display_frame = Empty()
            end

            VBox(
                display_frame,
                ButtonBox(
                    PushButton(Id(:ok), Yast::Label.OKButton),
                    PushButton(Id(:cancel), Yast::Label.CancelButton)
                )
            )
        end

        def create_dialog
            return false unless super
            reload_tables
            return true
        end

        # Event handlers

        # Set password for a gateway
        def psk_set_handler
            gw_ip = Yast::UI.QueryWidget(Id(:psk_table), :CurrentItem)
            new_pwd = SetClientPSKDialog.new.run
            return unless new_pwd
            IPSec.set_client_pwd(gw_ip, new_pwd)
            reload_tables
        end

        # Toggle show password.
        def psk_show_pwd_handler
            reload_tables
        end

        # Save certificate settings
        def cert_set_handler
            # Set certificate for a gateway
            gw_ip = Yast::UI.QueryWidget(Id(:cert_table), :CurrentItem)
            existing_setting = IPSec.get_client_certs[gw_ip]
            result = SetClientCertDialog.new(existing_setting[:cert], existing_setting[:key]).run
            return unless result
            IPSec.set_client_cert(gw_ip, result[0], result[1])
            reload_tables
        end

        # Make sure that tables are filled, then save all settings.
        def ok_handler
            if @require_psk
                missing_psks = IPSec.get_client_psks.select{ |ip, pass| pass == nil || pass == "" }
                if missing_psks.length > 0
                    Yast::Popup.Error(_("Shared keys for the following gateways are still missing:\n%s") %
                                        [missing_psks.keys.join(", ")])
                end
            elsif @require_cert
                missing_certs = IPSec.get_client_certs.select{ |ip, certkey| certkey[:key] == nil || certkey[:key] == "" }
                if missing_certs.length > 0
                    Yast::Popup.Error(_("Certificates for the following gateways are still missing:\n%s") %
                                        [missing_certs.keys.join(", ")])
                end
            end
            finish_dialog(nil)
        end

        private
            # Reload password/certificate tables.
            def reload_tables
                # Load PSKs
                psk_show_pwd = Yast::UI.QueryWidget(Id(:psk_show_pwd), :Value) == true
                psk_items = IPSec.get_client_psks.map { |gw_ip, pass|
                    Item(gw_ip, psk_show_pwd ? pass : _("(hidden)"))
                }
                Yast::UI.ChangeWidget(Id(:psk_table), :Items, psk_items)
                # Load certificates
                cert_items = IPSec.get_client_certs.map { |gw_ip, cert_and_key|
                    Item(gw_ip, cert_and_key[:cert], cert_and_key[:key])
                }
                Yast::UI.ChangeWidget(Id(:cert_table), :Items, cert_items)
            end
    end
end
