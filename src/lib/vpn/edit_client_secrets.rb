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
require "pp"
require "vpn/set_client_cert_dialog"
require "vpn/set_client_psk_dialog"
Yast.import "UI"
Yast.import "Icon"
Yast.import "Label"
Yast.import "Popup"

module VPN
    # Manage VPN client secrets.
    class EditClientSecretsDialog
        include Yast::UIShortcuts
        include Yast::I18n
        include Yast::Logger

        def initialize
            textdomain "vpn"
        end

        # Return nothing.
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
                psk_frame = Frame(_("Pre-shared key for gateways"), VBox(
                                MinSize(40, 8, Table(Id(:psk_table), Header(_("Gateway IP"), _("Pre-shared key"), []))),
                                HBox(
                                    PushButton(Id(:psk_set), _("Set")),
                                    CheckBox(Id(:psk_show_pwd), Opt(:notify), _("Show key")))))
                cert_frame = Frame(_("Certificate/key pair for gateways"), VBox(
                                MinSize(40, 8, Table(Id(:cert_table), Header(_("Gateway IP"), _("Certificate"), _("Key"), []))),
                                PushButton(Id(:cert_set), _("Set"))))

                display_frame = nil
                @require_psk = false
                @require_cert = false
                if IPSec.get_current_conn["scenario"] == :client_psk
                    display_frame = psk_frame
                    @require_psk = true
                else
                    display_frame = cert_frame
                    @require_cert = true
                end

                Yast::UI.OpenDialog(
                    Opt(:decorated),
                    VBox(
                        display_frame,
                        ButtonBox(
                            PushButton(Id(:ok), Yast::Label.OKButton),
                            PushButton(Id(:cancel), Yast::Label.CancelButton)
                        )
                    )
                )
                reload_tables
            end

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

            def ui_event_loop
                loop do
                    case Yast::UI.UserInput
                    when :psk_set
                        # Set password for a gateway
                        gw_ip = Yast::UI.QueryWidget(Id(:psk_table), :CurrentItem)
                        new_pwd = SetClientPSKDialog.new.run
                        if new_pwd == nil
                            redo
                        end
                        IPSec.set_client_pwd(gw_ip, new_pwd)
                        reload_tables
                    when :psk_show_pwd
                        reload_tables
                    when :cert_set
                        # Set certificate for a gateway
                        gw_ip = Yast::UI.QueryWidget(Id(:cert_table), :CurrentItem)
                        existing_setting = IPSec.get_client_certs[gw_ip]
                        result = SetClientCertDialog.new(existing_setting[:cert], existing_setting[:key]).run
                        if result == nil
                            redo
                        end
                        IPSec.set_client_cert(gw_ip, result[0], result[1])
                        reload_tables
                    when :ok
                        # Make sure that tables are filled
                        if @require_psk
                            missing_psks = IPSec.get_client_psks.select{ |ip, pass| pass == nil || pass == "" }
                            if missing_psks.length > 0
                                Yast::Popup.Error(_("Shared keys for the following gateways are still missing:\n%s") %
                                                  [missing_psks.keys.join(", ")])
                                redo
                            end
                        elsif @require_cert
                            missing_certs = IPSec.get_client_certs.select{ |ip, certkey| certkey[:key] == nil || certkey[:key] == "" }
                            if missing_certs.length > 0
                                Yast::Popup.Error(_("Certificates for the following gateways are still missing:\n%s") %
                                                  [missing_certs.keys.join(", ")])
                                redo
                            end
                        end
                        return
                    else
                        return
                    end
                end
            end
    end
end
