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
require "ui/dialog"
Yast.import "UI"
Yast.import "Label"
Yast.import "Popup"
Yast.import "Service"

module VPN
    # View log dialog displays current status about all IPSec connections.
    class ViewLogDialog < UI::Dialog
        include Yast::UIShortcuts
        include Yast::I18n
        include Yast::Logger

        def initialize
            super
            textdomain "vpn"
        end

        def dialog_options
            Opt(:decorated, :defaultsize)
        end

        def dialog_content
            VBox(
                Left(LogView(Id(:daemon_status), "VPN daemon status", 8, 0)),
                Left(LogView(Id(:conn_status), "All connection status", 8, 0)),
                Left(Label(Opt(:boldFont), _("The logs are refreshed automatically every 3 seconds."))),
                HBox(
                    PushButton(Id(:restart_daemon), _("Restart VPN Daemon")),
                    PushButton(Id(:finish), Yast::Label.FinishButton)
                )
            )
        end

        def create_dialog
            return false unless super
            refresh_status
            return true
        end

        # Event handlers.
        def user_input
            Yast::UI.TimeoutUserInput(3000)
        end

        # Refresh log views every 3 seconds, "timeout" is the magical word used by TimeoutUserInput.
        def timeout_handler
            refresh_status
        end

        # Restart IPSec daemon service.
        def restart_daemon_handler
            if Yast::Popup.ContinueCancelHeadline(
                _("Confirm daemon restart"),
                _("Existing connections will be interrupted.\n" +
                    "Do you still wish to continue?")
                )
                if !(Yast::Service.Active("strongswan") ? Yast::Service.Restart("strongswan") : Yast::Service.Start("strongswan"))
                    Yast::Popup.Error(_("Failed to restart IPSec daemon"))
                end
            end
        end

        def finish_handler
            finish_dialog(nil)
        end

        private
        # Read daemon status and refresh the content of log views.
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
    end
end
