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
# Summary: Display IPSec daemon and connection status.
# Authors: Howard Guo <hguo@suse.com>

require "yast"
require "date"
Yast.import "UI"
Yast.import "Icon"
Yast.import "Label"
Yast.import "Popup"
Yast.import "Service"

module VPN
    # View log dialog displays current status about all IPSec connections.
    class ViewLogDialog
        include Yast::UIShortcuts
        include Yast::I18n
        include Yast::Logger

        def initialize
            textdomain "vpn"
        end

        # Return VPN name string, or :cancel if the dialog is cancelled.
        def run
            return if !render_all
            begin
                return ui_event_loop
            ensure
                Yast::UI.CloseDialog()
            end
        end

        private
            def render_all
                Yast::UI.OpenDialog(
                    Opt(:decorated, :defaultsize),
                    VBox(
                        Left(LogView(Id(:daemon_status), "VPN daemon status", 8, 0)),
                        Left(LogView(Id(:conn_status), "All connection status", 8, 0)),
                        Left(Label(Opt(:boldFont), _("The logs are refreshed automatically every 3 seconds."))),
                        HBox(
                            PushButton(Id(:restart_daemon), _("Restart VPN Daemon")),
                            PushButton(Id(:finish), Yast::Label.FinishButton)
                        )
                    )
                )
                refresh_status
            end

            def refresh_status
                sh_daemon_status = Yast::SCR.Execute(Yast::Path.new(".target.bash_output"), "systemctl status strongswan")
                Yast::UI.ChangeWidget(Id(:daemon_status), :Value, sh_daemon_status["stdout"])

                sh_conn_status = Yast::SCR.Execute(Yast::Path.new(".target.bash_output"), "ipsec statusall 2>&1")
                if sh_conn_status["exit"].zero?
                    Yast::UI.ChangeWidget(Id(:conn_status), :Value, sh_conn_status["stdout"])
                else
                    Yast::UI.ChangeWidget(Id(:conn_status), :Value, _("Status not available: is the daemon running?"))
                end
            end
            
            # Return VPN name string, or :cancel if the dialog is cancelled.
            def ui_event_loop
                loop do
                    case Yast::UI.TimeoutUserInput(3000)
                    when :timeout
                        # Refresh log views every 3 seconds
                        refresh_status
                    when :restart_daemon
                        if Yast::Popup.ContinueCancelHeadline(
                            _("Confirm daemon restart"),
                            _("Existing connections will be interrupted.\n" +
                              "Do you still wish to continue?")
                            )
                            if !(Yast::Service.Active("strongswan") ? Yast::Service.Restart("strongswan") : Yast::Service.Start("strongswan"))
                                Yast::Popup.Error(_("Failed to restart IPSec daemon"))
                            end
                        end
                    else
                        return
                    end
                end
            end
    end
end
