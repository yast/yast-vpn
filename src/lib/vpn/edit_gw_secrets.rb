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
require "ui/dialog"
require "vpn/new_user_dialog"
Yast.import "UI"
Yast.import "Label"
Yast.import "Popup"

module VPN
    # Manage VPN gateway secrets across all scenarios.
    class EditGWSecretsDialog < UI::Dialog
        include Yast::UIShortcuts
        include Yast::I18n
        include Yast::Logger

        def initialize
            super
            textdomain "vpn"

            @require_psk = false
            @require_cert = false
            case IPSec.get_current_conn["scenario"]
            when :gw_psk, :gw_mobile
                @require_psk = true
            when :gw_cert, :gw_win
                @require_cert = true
            end
        end

        def dialog_options
            Opt(:decorated)
        end

        def dialog_content
            # Only display the settings relevant to current scenario
            frames = []
            case IPSec.get_current_conn["scenario"]
            when :gw_psk
                frames << mk_gw_psk_frame
            when :gw_cert
                frames << mk_gw_cert_frame
            when :gw_mobile
                frames += [mk_gw_psk_frame, mk_xauth_frame]
            when :gw_win
                frames += [mk_gw_cert_frame, mk_eap_frame]
            end

            VBox(
                *(frames.zip([VSpacing(1.0)].cycle).flatten),
                ButtonBox(
                    PushButton(Id(:ok), Yast::Label.OKButton),
                    PushButton(Id(:cancel), Yast::Label.CancelButton),
                )
            )
        end

        def create_dialog
            return false unless super
            # Load certificate
            gw_cert, gw_key = IPSec.get_gw_cert_and_key
            Yast::UI.ChangeWidget(Id(:gw_cert), :Value, gw_cert || "")
            Yast::UI.ChangeWidget(Id(:gw_cert_key), :Value, gw_key || "")

            reload_psk
            reload_tables
            return true
        end

        # Event handlers

        # Togglw show PSK password.
        def gw_show_pwd_handler
            reload_psk
        end

        # Toggle show EAP password.
        def eap_show_pwd_handler
            reload_tables
        end

        # Toggle show XAUTH password.
        def xauth_show_pwd_handler
            reload_tables
        end

        # Add an EAP user.
        def eap_add_handler
            result = NewUserDialog.new.run
            if result == nil
                return
            end
            IPSec.add_user_pass(:eap, result[0], result[1])
            reload_tables
        end

        # Remove the selected EAP user.
        def eap_del_handler
            username = Yast::UI.QueryWidget(Id(:eap_table), :CurrentItem)
            if username == nil
                Yast::Popup.Error(_("Please select a user to delete."))
                return
            end
            IPSec.del_user_pass(:eap, username)
            reload_tables
        end

        # Add an XAuth user.
        def xauth_add_handler
            result = NewUserDialog.new.run
            if result == nil
                return
            end
            IPSec.add_user_pass(:xauth, result[0], result[1])
            reload_tables
        end

        # Remove the selected XAuth user.
        def xauth_del_handler
            username = Yast::UI.QueryWidget(Id(:xauth_table), :CurrentItem)
            if username == nil
                Yast::Popup.Error(_("Please select a user to delete."))
                return
            end
            IPSec.del_user_pass(:xauth, username)
            reload_tables
        end

        # Save PSK and certificate settings. Note that XAUTH and EAP user lists are already saved.
        def ok_handler
            if @require_psk
                gw_pwd = Yast::UI.QueryWidget(Id(:gw_pwd), :Value)
                gw_pwd_enabled = Yast::UI.QueryWidget(Id(:gw_pwd), :Enabled)
                if gw_pwd == "" || !gw_pwd_enabled && IPSec.get_all_secrets[:gw_psk] == ""
                    Yast::Popup.Error(_("A pre-shared key is mandatory. Please enter a pre-shared key."))
                    return
                end
                if gw_pwd_enabled
                    IPSec.change_gw_pwd(gw_pwd)
                end
            end

            if @require_cert
                cert_path = Yast::UI.QueryWidget(Id(:gw_cert), :Value)
                cert_key_path = Yast::UI.QueryWidget(Id(:gw_cert_key), :Value)
                if cert_path == "" || cert_key_path == ""
                    Yast::Popup.Error(_("Please enter both certificate file path and key file path."))
                    return
                end
                IPSec.change_gw_cert(cert_path, cert_key_path)
            end
            finish_dialog(nil)
        end

        def select_gw_cert_handler
            path = Yast::UI.AskForExistingFile("/", "", _("Pick a PEM encoded certificate file"))
            Yast::UI.ChangeWidget(Id(:gw_cert), :Value, path) unless path.nil?
        end

        def select_gw_cert_key_handler
            path = Yast::UI.AskForExistingFile("/", "", _("Pick a PEM encoded certificate key file"))
            Yast::UI.ChangeWidget(Id(:gw_cert_key), :Value, path) unless path.nil?
        end

        private
        def mk_gw_psk_frame
            Frame(_("Gateway pre-shared key"), VBox(
                Left(MinWidth(40, InputField(Id(:gw_pwd), "", ""))),
                Left(CheckBox(Id(:gw_show_pwd), Opt(:notify), _("Show key")))))
        end

        def mk_gw_cert_frame
            Frame(_("Gateway certificate"), VBox(
                Left(MinWidth(40, HBox(
                    InputField(Id(:gw_cert), _("Path to certificate file"), ""),
                    Bottom(PushButton(Id(:select_gw_cert), _("Pick..")))))),
                Left(MinWidth(40, HBox(
                    InputField(Id(:gw_cert_key), _("Path to certificate key file"), ""),
                    Bottom(PushButton(Id(:select_gw_cert_key), _("Pick.."))))))))
        end

        def mk_xauth_frame
            Frame(_("User credentials for Android, iOS, MacOS X clients"), VBox(
                MinSize(40, 8, Table(Id(:xauth_table), Header(_("Username"), _("Password"), []))),
                HBox(
                    PushButton(Id(:xauth_add), _("Add")),
                    PushButton(Id(:xauth_del), _("Delete")),
                    CheckBox(Id(:xauth_show_pwd), Opt(:notify), _("Show Password")))))
        end

        def mk_eap_frame
            Frame(_("User credentials for Windows 7, Windows 8 clients"), VBox(
                MinSize(40, 8, Table(Id(:eap_table), Header(_("Username"), _("Password"), []))),
                HBox(
                    PushButton(Id(:eap_add), _("Add")),
                    PushButton(Id(:eap_del), _("Delete")),
                    CheckBox(Id(:eap_show_pwd), Opt(:notify), _("Show Password")))))
        end

        # Reload gateway PSK text input.
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
    end
end
