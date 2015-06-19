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
# Summary: Display a dialog for managing VPN gateway secrets.
# Authors: Howard Guo <hguo@suse.com>

require "yast"
require "vpn/new_user_dialog"
Yast.import "UI"
Yast.import "Icon"
Yast.import "Label"
Yast.import "Popup"

module VPN
    # Manage VPN gateway secrets across all scenarios.
    class EditGWSecretsDialog
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
                gw_psk_frame = Frame(_("Gateway pre-shared key"), VBox(
                                   Left(MinWidth(40, InputField(Id(:gw_pwd), "", ""))),
                                   Left(CheckBox(Id(:gw_show_pwd), Opt(:notify), _("Show key")))))
                gw_cert_frame = Frame(_("Gateway certificate"), VBox(
                                    Left(MinWidth(40, InputField(Id(:gw_cert), _("Path to certificate file"), ""))),
                                    Left(MinWidth(40, InputField(Id(:gw_cert_key), _("Path to certificate key file"), "")))))
                xauth_frame = Frame(_("User credentials for Android, iOS, MacOS X clients"), VBox(
                              MinSize(40, 8, Table(Id(:xauth_table), Header(_("Username"), _("Password"), []))),
                              HBox(
                                  PushButton(Id(:xauth_add), _("Add")),
                                  PushButton(Id(:xauth_del), _("Delete")),
                                  CheckBox(Id(:xauth_show_pwd), Opt(:notify), _("Show Password")))))
                eap_frame = Frame(_("User credentials for Windows 7, Windows 8 clients"), VBox(
                            MinSize(40, 8, Table(Id(:eap_table), Header(_("Username"), _("Password"), []))),
                            HBox(
                                PushButton(Id(:eap_add), _("Add")),
                                PushButton(Id(:eap_del), _("Delete")),
                                CheckBox(Id(:eap_show_pwd), Opt(:notify), _("Show Password")))))

                # Only display the settings relevant to current scenario
                @psk_required = false
                @cert_required = false
                frames = []
                case IPSec.get_current_conn["scenario"]
                when :gw_psk
                    @psk_required = true
                    frames += [gw_psk_frame]
                when :gw_cert
                    @cert_required = true
                    frames += [gw_cert_frame]
                when :gw_mobile
                    @psk_required = true
                    frames += [gw_psk_frame, xauth_frame]
                when :gw_win
                    @cert_required = true
                    frames += [gw_cert_frame, eap_frame]
                end

                Yast::UI.OpenDialog(
                    Opt(:decorated),
                    VBox(
                        *(frames.zip([VSpacing(1.0)].cycle).flatten),
                        ButtonBox(
                            PushButton(Id(:ok), Yast::Label.OKButton),
                            PushButton(Id(:cancel), Yast::Label.CancelButton),
                        )
                    )
                )

                # Load certificate
                gw_cert_and_key = IPSec.get_gw_cert_and_key
                if gw_cert_and_key == nil
                    Yast::UI.ChangeWidget(Id(:gw_cert), :Value, "")
                    Yast::UI.ChangeWidget(Id(:gw_cert_key), :Value, "")
                else
                    Yast::UI.ChangeWidget(Id(:gw_cert), :Value, gw_cert_and_key[0])
                    Yast::UI.ChangeWidget(Id(:gw_cert_key), :Value, gw_cert_and_key[1])
                end

                reload_psk
                reload_tables
            end

            def reload_psk
                gw_show_pwd = Yast::UI.QueryWidget(Id(:gw_show_pwd), :Value) == true
                gw_pwd = IPSec.get_all_secrets[:gw_psk]
                gw_pwd = gw_pwd == nil ? "" : gw_pwd
                Yast::UI.ChangeWidget(Id(:gw_pwd), :Value, gw_show_pwd ? gw_pwd : _("(hidden)"))
                Yast::UI.ChangeWidget(Id(:gw_pwd), :Enabled, gw_show_pwd)
            end

            # Reload username/password tables.
            def reload_tables
                # Load XAuth
                xauth_show_pwd = Yast::UI.QueryWidget(Id(:xauth_show_pwd), :Value) == true
                xauth_items = IPSec.get_all_secrets[:xauth].map { |username, pass|
                    Item(username, xauth_show_pwd ? pass : _("(hidden)"))
                }
                Yast::UI.ChangeWidget(Id(:xauth_table), :Items, xauth_items)
                # Load EAP
                eap_show_pwd = Yast::UI.QueryWidget(Id(:eap_show_pwd), :Value) == true
                eap_items = IPSec.get_all_secrets[:eap].map { |username, pass|
                    Item(username, eap_show_pwd ? pass : _("(hidden)"))
                }
                Yast::UI.ChangeWidget(Id(:eap_table), :Items, eap_items)
            end

            def ui_event_loop
                loop do
                    case Yast::UI.UserInput
                    when :gw_show_pwd
                        reload_psk
                    when :eap_add
                        # Add an EAP user
                        result = NewUserDialog.new.run
                        if result == nil
                            redo
                        end
                        IPSec.add_user_pass(:eap, result[0], result[1])
                        reload_tables
                    when :eap_del
                        # Remove the selected EAP user
                        username = Yast::UI.QueryWidget(Id(:eap_table), :CurrentItem)
                        if username == nil
                            redo
                        end
                        IPSec.del_user_pass(:eap, username)
                        reload_tables
                    when :eap_show_pwd
                        reload_tables
                    when :xauth_add
                        # Add an XAuth user
                        result = NewUserDialog.new.run
                        if result == nil
                            redo
                        end
                        IPSec.add_user_pass(:xauth, result[0], result[1])
                        reload_tables
                    when :xauth_del
                        # Remove the selected XAuth user
                        username = Yast::UI.QueryWidget(Id(:xauth_table), :CurrentItem)
                        if username == nil
                            redo
                        end
                        IPSec.del_user_pass(:xauth, username)
                        reload_tables
                    when :xauth_show_pwd
                        reload_tables
                    when :ok
                        if @psk_required
                            gw_pwd = Yast::UI.QueryWidget(Id(:gw_pwd), :Value)
                            gw_pwd_enabled = Yast::UI.QueryWidget(Id(:gw_pwd), :Enabled) == true
                            if gw_pwd == "" || !gw_pwd_enabled && IPSec.get_all_secrets[:gw_psk] == ""
                                Yast::Popup.Error(_("A pre-shared key is mandatory. Please enter a pre-shared key."))
                                redo
                            end
                            if gw_pwd_enabled
                                IPSec.change_gw_pwd(gw_pwd)
                            end
                        end

                        if @cert_required
                            cert_path = Yast::UI.QueryWidget(Id(:gw_cert), :Value)
                            cert_key_path = Yast::UI.QueryWidget(Id(:gw_cert_key), :Value)
                            if cert_path == "" || cert_key_path == ""
                                Yast::Popup.Error(_("Please enter both certificate file path and key file path."))
                                redo
                            end
                            IPSec.change_gw_cert(cert_path, cert_key_path)
                        end
                        # XAuth and EAP user list are already saved
                        return
                    else
                        return
                    end
                end
            end
    end
end
