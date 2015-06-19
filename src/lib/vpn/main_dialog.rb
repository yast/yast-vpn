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
# Summary: The main dialog, showing a list of all connections and allow user to modify their configuration.
# Authors: Howard Guo <hguo@suse.com>

require "yast"
require "vpn/new_vpn_dialog"
require "vpn/view_log_dialog"
require "vpn/edit_client_secrets"
require "vpn/edit_gw_secrets"
require "vpn/ipsec"
Yast.import "UI"
Yast.import "Icon"
Yast.import "Label"
Yast.import "Popup"

module VPN
    # Show a list of all connections and allow user to modify the connection configuration.
    class MainDialog
        include Yast::UIShortcuts
        include Yast::I18n
        include Yast::Logger

        # If can_apply is true, settings will be applied when Apply button is clicked.
        def initialize(can_apply)
            textdomain "vpn"
            @can_apply = can_apply
        end

        # Return :finish on save, or :abort on abort.
        def run
            render_all
            begin
                return ui_event_loop
            ensure
                Yast::UI.CloseDialog()
            end
        end

        private
            # Render global options, connection list, and connection configuration frames.
            def render_all
                Yast::UI.OpenDialog(
                    Opt(:decorated, :defaultsize),
                    VBox(
                        Left(HBox(
                            Yast::Icon::Simple("yast-device-tree"),
                            Heading(_("VPN Gateway and Client"))
                        )),
                        HBox(
                            # Left side: global config & connection management
                            HWeight(35, VBox(
                                VSpacing(1),
                                Frame(_("Global Configuration"),
                                    VBox(
                                        Left(CheckBox(Id(:enable_daemon), _("Enable VPN daemon"), Yast::IPSecConf.DaemonEnabled)),
                                        Left(HBox(
                                            CheckBox(Id(:fix_mss), _("Reduce TCP MSS"), Yast::IPSecConf.TCPMSS1024Enabled),
                                            PushButton(Id(:fix_mss_help), _("?"))))
                                )),
                                Frame(_("All VPNs"), ReplacePoint(Id(:conn_list), Empty())),
                                VBox(
                                    HBox(
                                        PushButton(Id(:new_vpn), _("New VPN")),
                                        PushButton(Id(:del_vpn), _("Delete VPN"))
                                    ),
                                    PushButton(Id(:view_log), _("View Connection Status"))
                                )
                            )),
                            # Right side: connection config editor
                            HWeight(65, ReplacePoint(Id(:conn_conf), Empty()))
                        ),
                        HBox(
                            PushButton(Id(:ok), Yast::Label.OKButton),
                            PushButton(Id(:abort), Yast::Label.AbortButton)
                        )
                    )
                )
                render_conn_list
                render_conn_conf
            end

            # Render a table of configured gateway and client connections.
            def render_conn_list
                Yast::UI.ReplaceWidget(Id(:conn_list), VBox(
                    Table(Id(:conn_table), Opt(:immediate),
                        Header(_("Name"), _("Description")),
                        IPSec.get_all_conns.map { |name, conn|
                            Item(name, IPSec.get_friendly_desc(conn))
                        }
                    )
                ))
                if IPSec.get_current_conn != nil
                    Yast::UI.ChangeWidget(Id(:conn_table), :CurrentItem, IPSec.get_current_conn["name"])
                end
            end

            # Render configuration controls for the chosen connection.
            def render_conn_conf
                conn = IPSec.get_current_conn
                if conn == nil
                    no_conn = Label(_("Click 'New VPN' to create a gateway or client."))
                    Yast::UI.ReplaceWidget(Id(:conn_conf), HVCenter(no_conn))
                    return
                end

                conn_type = IPSec.get_current_conn_type

                # Make widgets for connection configuration
                netaccess_group = RadioButtonGroup(Id(:conn_access),
                    VBox(
                        Left(RadioButton(Id(:conn_access_all4), Opt(:notify), _("All IPv4 networks (0.0.0.0/0)"))),
                        Left(RadioButton(Id(:conn_access_all6), Opt(:notify), _("All IPv6 networks (::/0)"))),
                        Left(HBox(
                            RadioButton(Id(:conn_access_limited), Opt(:notify), _("Limited CIDRs, comma separated:")),
                            MinWidth(12, InputField(Id(:conn_access_subnet), Opt(:notify), "", ""))
                        )),
                    )
                )
                controls = [
                    Left(Label(Opt(:boldFont), _("Connection name: ") + conn["name"])),
                    Frame(_("Type"), RadioButtonGroup(Id(:conn_type),
                        VBox(
                            Left(RadioButton(Id(:conn_type_gateway), Opt(:notify), _("Gateway (Server)"))),
                            Left(RadioButton(Id(:conn_type_client), Opt(:notify), _("Client")))
                        )
                    ))
                ]

                if conn_type == :gateway
                    controls += [
                        Frame(_("The scenario is"), RadioButtonGroup(Id(:conn_gw_scenario),
                            VBox(
                                Left(RadioButton(Id(:conn_gw_psk), Opt(:notify), _("Secure communication with a pre-shared key"))),
                                Left(RadioButton(Id(:conn_gw_cert), Opt(:notify), _("Secure communication with a certificate"))),
                                Left(RadioButton(Id(:conn_gw_mobile), Opt(:notify), _("Provide access to Android, iOS, MacOS X clients"))),
                                Left(RadioButton(Id(:conn_gw_win), Opt(:notify), _("Provide access to Windows 7, Windows 8 clients"))),
                                VSpacing(1),
                                Left(PushButton(Id(:edit_gw_secrets), _("Edit Credentials")))
                            )
                        )),
                        Frame(_("Provide VPN clients access to"), netaccess_group),
                        Frame(_("Clients' address pool (e.g. 192.168.100.0/24)"), MinWidth(12, InputField(Id(:conn_sourceip), Opt(:hstretch, :notify), "", "")))
                    ]
                else
                    controls += [
                        Frame(_("The gateway requires authentication"), RadioButtonGroup(Id(:conn_client_scenario),
                            VBox(
                                Left(RadioButton(Id(:conn_client_psk), Opt(:notify), _("By a pre-shared key"))),
                                Left(RadioButton(Id(:conn_client_cert), Opt(:notify), _("By a certificate"))),
                                VSpacing(1),
                                Left(InputField(Id(:conn_right), Opt(:hstretch, :notify), _("VPN gateway IP"), "")),
                                Left(PushButton(Id(:edit_client_secrets), _("Edit Credentials")))
                            )
                        )),
                        Frame(_("Use the VPN tunnel to access"), netaccess_group),
                    ]
                end
                Yast::UI.ReplaceWidget(Id(:conn_conf), Top(VSquash(VBox(*controls))))

                # Fill up the widget with actual configuration value
                # network access
                subnet = conn_type == :gateway ? "leftsubnet" : "rightsubnet"
                if conn[subnet] == "0.0.0.0/0"
                    Yast::UI.ChangeWidget(Id(:conn_access), :CurrentButton, :conn_access_all4)
                    Yast::UI.ChangeWidget(Id(:conn_access_subnet), :Value, "")
                    Yast::UI.ChangeWidget(Id(:conn_access_subnet), :Enabled, false)
                elsif conn[subnet] == "::/0"
                    Yast::UI.ChangeWidget(Id(:conn_access), :CurrentButton, :conn_access_all6)
                    Yast::UI.ChangeWidget(Id(:conn_access_subnet), :Value, "")
                    Yast::UI.ChangeWidget(Id(:conn_access_subnet), :Enabled, false)
                else
                    Yast::UI.ChangeWidget(Id(:conn_access), :CurrentButton, :conn_access_limited)
                    Yast::UI.ChangeWidget(Id(:conn_access_subnet), :Value, conn[subnet])
                    Yast::UI.ChangeWidget(Id(:conn_access_subnet), :Enabled, true)
                end
                # connection type
                if conn_type == :gateway
                    Yast::UI.ChangeWidget(Id(:conn_type), :CurrentButton, :conn_type_gateway)
                else
                    Yast::UI.ChangeWidget(Id(:conn_type), :CurrentButton, :conn_type_client)
                end
                # scenario
                case conn["scenario"]
                    when :gw_psk
                        Yast::UI.ChangeWidget(Id(:conn_gw_scenario), :CurrentButton, :conn_gw_psk)
                    when :gw_cert
                        Yast::UI.ChangeWidget(Id(:conn_gw_scenario), :CurrentButton, :conn_gw_cert)
                    when :gw_mobile
                        Yast::UI.ChangeWidget(Id(:conn_gw_scenario), :CurrentButton, :conn_gw_mobile)
                    when :gw_win
                        Yast::UI.ChangeWidget(Id(:conn_gw_scenario), :CurrentButton, :conn_gw_win)
                    when :client_psk
                        Yast::UI.ChangeWidget(Id(:conn_client_scenario), :CurrentButton, :conn_client_psk)
                    when :client_cert
                        Yast::UI.ChangeWidget(Id(:conn_client_scenario), :CurrentButton, :conn_client_cert)
                end
                Yast::UI.RecalcLayout
                # IP pool
                Yast::UI.ChangeWidget(Id(:conn_sourceip), :Value, conn["rightsourceip"])
                # client - gateway IP
                Yast::UI.ChangeWidget(Id(:conn_right), :Value, conn["right"])
            end

            def ui_event_loop
                loop do
                    case Yast::UI.UserInput
                    when :fix_mss_help
                        Yast::Popup.LongMessage(_("If VPN clients have trouble accessing certain Internet sites, " +
                            "it is possible that the affected hosts prevent automatic MTU (maximum transmission " +
                            "unit) discovery due to incorrect firewall configuration.\n" +
                            "Reducing TCP-MSS will correct the situation; however, the available bandwidth will be " +
                            "reduced by about 10%."))
                    when :new_vpn
                        # Prompt for a VPN connection name and create a new VPN
                        if NewVPNDialog.new.run == :ok
                            render_conn_list
                            render_conn_conf
                        end
                    when :del_vpn
                        # Delete the chosen VPN connection
                        if IPSec.get_current_conn == nil
                            redo
                        end
                        if !Yast::Popup.ContinueCancelHeadline(
                            _("Delete connection"),
                            _("Are you sure to delete connection ") + IPSec.get_current_conn["name"] + "?"
                        )
                            redo
                        end
                        IPSec.del_conn
                        render_conn_list
                        render_conn_conf
                    when :view_log
                        # Display IPSec daemon log and all connection status
                        ViewLogDialog.new.run
                    when :ok
                        # Apply settings
                        # Check for incomplete configuration
                        scr_conf, unfilled_params = IPSec.make_scr_conf
                        if unfilled_params.length > 0
                            Yast::Popup.Error(_("Please complete configuration for the following connections:\n" +
                                                unfilled_params.keys.join(", ")))
                            redo
                        end
                        # Consider enabling the daemon
                        enable_daemon = Yast::UI.QueryWidget(Id(:enable_daemon), :Value) == true
                        if !enable_daemon && scr_conf.length > 0 &&
                                Yast::Popup.YesNo(_("There are VPN connections but the daemon is not enabled.\n" +
                                      "Would you like to enable the VPN daemon?"))
                            Yast::UI.ChangeWidget(Id(:enable_daemon), :Value, true)
                            enable_daemon = true
                        end
                        # Save new settings and apply
                        Yast::IPSecConf.Import({
                            "enable_ipsec" => enable_daemon,
                            "tcp_mss_1024" => !!Yast::UI.QueryWidget(:fix_mss, :Value),
                            "ipsec_conns" => scr_conf,
                            "ipsec_secrets" => IPSec.make_scr_secrets
                        })
                        # Settings are memorised but not yet applied
                        if !@can_apply
                            return :finish
                        end
                        scr_success = Yast::IPSecConf.Write
                        # Ask user whether he wants to view daemon log
                        popup_msg = nil
                        if scr_success
                            popup_msg = _("Settings have been successfully applied.")
                        else
                            popup_msg = _("Failed to configure IPSec daemon.")
                        end
                        if enable_daemon
                            popup_msg += "\n" + _("Would you like to view daemon log and connection status?")
                            if Yast::Popup.YesNo(popup_msg)
                                ViewLogDialog.new.run
                            else
                                return :finish
                            end
                        else
                            Yast::Popup.Message(popup_msg)
                            return :finish
                        end
                    when :abort
                        # Do nothing and close this YaST module
                        if Yast::Popup.ReallyAbort(true)
                            return :abort
                        end
                    when :conn_table
                        # Select a connection from connection list
                        conn_name = Yast::UI.QueryWidget(Id(:conn_table), :CurrentItem)
                        if conn_name != nil
                            IPSec.switch_conn(conn_name)
                            render_conn_conf
                        end
                    when :conn_access_all4
                        # Gateway: give access to all IPv4 networks to VPN clients
                        # Client: use VPN gateway for all IPv4 network access
                        if IPSec.get_current_conn_type == :gateway
                            IPSec.change_conn_param("leftsubnet", "0.0.0.0/0")
                        else
                            IPSec.change_conn_param("rightsubnet", "0.0.0.0/0")
                        end
                        # Disable specific subnet input
                        Yast::UI.ChangeWidget(Id(:conn_access_subnet), :Enabled, false)
                        Yast::UI.ChangeWidget(Id(:conn_access_subnet), :Value, "")
                    when :conn_access_all6
                        # Gateway: give access to all IPv6 networks to VPN clients
                        # Client: use VPN gateway for all IPv6 network access
                        if IPSec.get_current_conn_type == :gateway
                            IPSec.change_conn_param("leftsubnet", "::/0")
                        else
                            IPSec.change_conn_param("rightsubnet", "::/0")
                        end
                        # Disable specific subnet input
                        Yast::UI.ChangeWidget(Id(:conn_access_subnet), :Enabled, false)
                        Yast::UI.ChangeWidget(Id(:conn_access_subnet), :Value, "")
                    when :conn_access_limited
                        # Enable the text field for subnet input
                        Yast::UI.ChangeWidget(Id(:conn_access_subnet), :Enabled, true)
                    when :conn_access_subnet
                        # Gateway: specify networks (CIDRs) tunneled through IPSec
                        # Client: specify networks (CIDRs) accessed via IPSec tunnel
                        subnet = Yast::UI.QueryWidget(Id(:conn_access_subnet), :Value)
                        if IPSec.get_current_conn_type == :gateway
                            IPSec.change_conn_param("leftsubnet", subnet)
                        else
                            IPSec.change_conn_param("rightsubnet", subnet)
                        end
                    when :conn_type_gateway
                        # Switch VPN connection type to gateway
                        if IPSec.get_current_conn_type == :gateway
                            redo
                        end
                        IPSec.change_conn_type(:gateway)
                        render_conn_list
                        render_conn_conf
                    when :conn_type_client
                        # Switch VPN connection type to client
                        if IPSec.get_current_conn_type == :client
                            redo
                        end
                        IPSec.change_conn_type(:client)
                        render_conn_list
                        render_conn_conf
                    when :conn_right
                        # Set gateway IP for client
                        right_ip = Yast::UI.QueryWidget(Id(:conn_right), :Value)
                        IPSec.change_conn_param("right", right_ip)
                    when :conn_sourceip
                        # Set client IP pool for gateway
                        source_ip = Yast::UI.QueryWidget(Id(:conn_sourceip), :Value)
                        IPSec.change_conn_param("rightsourceip", source_ip)
                    when :edit_client_secrets
                        # Edit VPN client passwords/certificates
                        right_ip = Yast::UI.QueryWidget(Id(:conn_right), :Value)
                        if right_ip == nil || right_ip.strip == ""
                            Yast::Popup.Error(_("Please enter gateway IP before editing credentials."))
                            redo
                        end
                        EditClientSecretsDialog.new.run
                    when :edit_gw_secrets
                        # Edit VPN gateway credentials/passwords/certificates
                        EditGWSecretsDialog.new.run
                    when :conn_gw_psk
                        # Change gateway type to site2site PSK
                        if IPSec.get_current_conn["scenario"] == :gw_psk
                            redo
                        end
                        IPSec.change_scenario(:gw_psk)
                        render_conn_list
                        render_conn_conf
                    when :conn_gw_cert
                        # Change gateway type to site2site certificate
                        if IPSec.get_current_conn["scenario"] == :gw_cert
                            redo
                        end
                        IPSec.change_scenario(:gw_cert)
                        render_conn_list
                        render_conn_conf
                    when :conn_gw_mobile
                        # Change gateway type to android/apple gateway
                        if IPSec.get_current_conn["scenario"] == :gw_mobile
                            redo
                        end
                        IPSec.change_scenario(:gw_mobile)
                        render_conn_list
                        render_conn_conf
                    when :conn_gw_win
                        # Change gateway type to windows gateway
                        if IPSec.get_current_conn["scenario"] == :gw_win
                            redo
                        end
                        IPSec.change_scenario(:gw_win)
                        render_conn_list
                        render_conn_conf
                    when :conn_client_psk
                        # Change client type to site2site PSK
                        if IPSec.get_current_conn["scenario"] == :client_psk
                            redo
                        end
                        IPSec.change_scenario(:client_psk)
                        render_conn_list
                        render_conn_conf
                    when :conn_client_cert
                        # Change client type to site2site certificate
                        if IPSec.get_current_conn["scenario"] == :client_cert
                            redo
                        end
                        IPSec.change_scenario(:client_cert)
                        render_conn_list
                        render_conn_conf
                    else
                        return :abort
                    end
                end
            end
    end
end
