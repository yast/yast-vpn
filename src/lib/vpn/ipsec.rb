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
# Summary: Functions and routines for manipulating IPSec connection configuration.
# Authors: Howard Guo <hguo@suse.com>

require "yast"
Yast.import "Popup"
Yast.import "IPSecConf"

module VPN
    # Functions and routines for reading and modifying IPSec connections and secrets.
    class IPSecClass
        include Yast::I18n
        include Yast::Logger

        # Template configuration for creating new gateway/client connections. Nil's are blanks to be filled.
        SCENARIO_TEMPLATES = {
            :gw_psk => {
                "auto" => "add",
                "keyexchange" => "ikev2",
                "left" => "%defaultroute",
                "leftauth" => "psk",
                "leftsubnet" => nil,
                "right" => "%any",
                "rightauth" => "psk",
                "rightsourceip" => nil,
                "fragmentation" => "yes",
                "dpdaction" => "clear",
                "dpdtimeout" => "600",
                "dpddelay" => "60",
            },
            :gw_cert => {
                "auto" => "add",
                "keyexchange" => "ikev2",
                "left" => "%defaultroute",
                "leftcert" => nil,
                "leftauth" => "pubkey",
                "leftsubnet" => nil,
                "right" => "%any",
                "rightcert" => nil,
                "rightsourceip" => nil,
                "rightauth" => "pubkey",
                "fragmentation" => "yes",
                "dpdaction" => "clear",
                "dpdtimeout" => "600",
                "dpddelay" => "60",
            },
            :gw_mobile => {
                "auto" => "add",
                "keyexchange" => "ikev1",
                "left" => "%defaultroute",
                "leftauth" => "psk",
                "leftsubnet" => nil,
                "right" => "%any",
                "rightauth" => "psk",
                "rightauth2" => "xauth",
                "rightsourceip" => nil,
                "fragmentation" => "yes",
                "dpdaction" => "clear",
                "dpdtimeout" => "600",
                "dpddelay" => "60",
            },
            :gw_win => {
                "auto" => "add",
                "keyexchange" => "ikev2",
                "rekey" => "no",
                "left" => "%defaultroute",
                "leftcert" => nil,
                "leftauth" => "pubkey",
                "leftsubnet" => nil,
                "right" => "%any",
                "rightsendcert" => "never",
                "rightauth" => "eap-mschapv2",
                "rightsourceip" => nil,
                "eap_identity" => "%any",
                "esp" => "aes256-sha1!",
                "ike" => "aes256-sha1-modp1024!",
                "fragmentation" => "yes",
                "dpdaction" => "clear",
                "dpdtimeout" => "600",
                "dpddelay" => "60",
            },
            :client_psk => {
                "auto" => "start",
                "keyexchange" => "ikev2",
                "left" => "%defaultroute",
                "leftauth" => "psk",
                "leftsourceip" => "%config",
                "right" => nil,
                "rightsubnet" => nil,
                "rightauth" => "psk",
                "fragmentation" => "yes",
                "dpdtimeout" => "600",
                "dpddelay" => "60",
                "dpdaction" => "restart",
                "closeaction" => "restart",
                "keyingtries" => "%forever"
            },
            :client_cert => {
                "auto" => "start",
                "keyexchange" => "ikev2",
                "left" => "%defaultroute",
                "leftsourceip" => "%config",
                "leftcert" => nil,
                "leftauth" => "pubkey",
                "right" => nil,
                "rightcert" => nil,
                "rightsubnet" => nil,
                "rightauth" => "pubkey",
                "fragmentation" => "yes",
                "dpdtimeout" => "600",
                "dpddelay" => "60",
                "dpdaction" => "restart",
                "closeaction" => "restart",
                "keyingtries" => "%forever"
            },
        }

        # These attributes are used to match existing configuration against the recognised scenarios.
        # They are basically SCENARIO_TEMPLATES without blanks to fill.
        KNOWN_SCENARIOS = Hash[SCENARIO_TEMPLATES.map { |scenario, conf|
            [scenario, conf.select{ |key, val| val != nil }]
        }]

        # Match the IPSec configuration against known scenarios, return the matching scenario name, or nil if there is none.
        def determine_scenario(conf)
            key, _conf = KNOWN_SCENARIOS.find {|scenario_key, scenario_conf|
                has_all_necessary_keys = (scenario_conf.keys - conf.keys).empty?
                match_necessary_keys = conf.none?{|cfg_key, cfg_val|
                    scenario_conf.has_key?(cfg_key) && scenario_conf[cfg_key] != cfg_val
                }
                has_all_necessary_keys && match_necessary_keys
            }
            return key
        end

        # Retrieve scenario-specific parameters from IPSec configuration.
        def get_scenario_specific_params(scenario, conf)
            case scenario
            when :gw_psk
                return {
                    "leftsubnet" => conf.fetch("leftsubnet", "0.0.0.0/0"),
                    "rightsourceip" => conf.fetch("rightsourceip", "")
                }
            when :gw_cert
                return {
                    "leftcert" => conf.fetch("leftcert", ""),
                    "rightcert" => conf.fetch("rightcert", ""),
                    "leftsubnet" => conf.fetch("leftsubnet", "0.0.0.0/0"),
                    "rightsourceip" => conf.fetch("rightsourceip", "")
                }
            when :gw_mobile
                return {
                    "leftsubnet" => conf.fetch("leftsubnet", "0.0.0.0/0"),
                    "rightsourceip" => conf.fetch("rightsourceip", "")
                }
            when :gw_win
                return {
                    "leftcert" => conf.fetch("leftcert", ""),
                    "leftsubnet" => conf.fetch("leftsubnet", "0.0.0.0/0"),
                    "rightsourceip" => conf.fetch("rightsourceip", "")
                }
            when :client_psk
                return {
                    "right" => conf.fetch("right", "0.0.0.0/0"),
                    "rightsubnet" => conf.fetch("rightsubnet", "0.0.0.0/0")
                }
            when :client_cert
                return {
                    "leftcert" => conf.fetch("leftcert", ""),
                    "right" => conf.fetch("right", "0.0.0.0/0"),
                    "rightcert" => conf.fetch("rightcert", ""),
                    "rightsubnet" => conf.fetch("rightsubnet", "0.0.0.0/0")
                }
            end
            raise "get_scenario_specific_params cannot deal with scenario " + scenario.to_s
        end

        # Return a user-friendly brief description of the connection.
        def get_friendly_desc(conf)
            case conf["scenario"]
            when :gw_psk
                return _("Gateway - PSK")
            when :gw_cert
                return _("Gateway - Certificate")
            when :gw_mobile
                return _("Gateway - Mobile clients")
            when :gw_win
                return _("Gateway - Windows clients")
            when :client_psk
                return _("Client - PSK")
            when :client_cert
                return _("Client - Certificate")
            else
                raise "get_friendly_desc cannot deal with configuration " + conf.to_s
            end
        end

        # Initialize but does not yet load IPSec connections and secrets from SCR backend.
        def initialize
            textdomain "vpn"
        end

        # (Re)load IPSec connections and secrets from SCR backend. Does not reload SCR backend itself.
        def reload
            @all_conns = {}
            # Load parameters from connections of known scenarios
            conns = Yast::IPSecConf.GetIPSecConnections
            conns ||= {}
            has_unsupported_scenario = false
            conns.each { | name, conf|
                scenario = determine_scenario(conf)
                if scenario == nil
                    has_unsupported_scenario = true
                    log.info "The connection is not supported: " + name
                else
                    conn_conf = {"name" => name, "scenario" => scenario}
                    @all_conns[name] = conn_conf.merge(get_scenario_specific_params(scenario, conf))
                end
            }
            if has_unsupported_scenario || !Yast::IPSecConf.GetUnsupportedConfiguration.empty? ||
                !Yast::IPSecConf.GetUnsupportedSecrets.empty?
                Yast::Popup.LongWarning(_("ipsec.conf and ipsec.secrets have been manipulated outside of this module.\n" +
                    "Continue using the module will remove your customisation."))
            end
            log.info "Loaded IPSec connections: #{@all_conns}"
            # By default, look at the first connection
            @curr_conn_name = @all_conns.keys.first unless @all_conns[@curr_conn_name]
            # Assort the IPSec secrets
            orig_secrets = Yast::IPSecConf.GetIPSecSecrets
            orig_secrets ||= {}
            @all_secrets = {
                :xauth => {}, :eap => {},
                :psk => {}, :gw_psk => "", :rsa => {}, :gw_rsa => ""
            }
            # username vs password
            orig_secrets.fetch("xauth", []).each { |entry|
                @all_secrets[:xauth][entry["id"]] = entry["secret"]
            }
            orig_secrets.fetch("eap", []).each { |entry|
                @all_secrets[:eap][entry["id"]] = entry["secret"]
            }
            # Separate gateway PSK from remote gateway PSKs
            orig_secrets.fetch("psk", []).each { |psk_key|
                if psk_key["id"] == "%any" || psk_key["id"] == ""
                    # This is the gateway PSK
                    # The YaST module supports at most one gateway PSK
                    @all_secrets[:gw_psk] = psk_key["secret"]
                else
                    # This is a PSK of remote gateway
                    @all_secrets[:psk][psk_key["id"]] = psk_key["secret"]
                end
            }
            # Separate gateway certificate from remote gateway certificates
            orig_secrets.fetch("rsa", []).each { |rsa_key|
                if rsa_key["id"] == "%any" || rsa_key["id"] == ""
                    @all_secrets[:gw_rsa] = rsa_key["secret"]
                else
                    @all_secrets[:rsa][rsa_key["id"]] = rsa_key["secret"]
                end
            }
        end

        # Return all connection configuration.
        def get_all_conns
            return @all_conns
        end

        # Change the current connection.
        def switch_conn(conn_name)
            @curr_conn_name = conn_name
        end

        # Get the configuration (hash) of the current connection.
        def get_current_conn
            return @all_conns[@curr_conn_name]
        end

        ALL_GATEWAY_SCENARIOS = [:gw_psk, :gw_cert, :gw_mobile, :gw_win]

        # Return :gateway if the scenario indicates a gateway connection. Otherwise :client.
        def get_scenario_conn_type(scenario)
            ALL_GATEWAY_SCENARIOS.include?(scenario) ? :gateway : :client
        end

        # Return :gateway if the current connection is a gateway connection. Otherwise :client.
        def get_current_conn_type
            return get_scenario_conn_type(get_current_conn["scenario"])
        end

        # Create a new connection, by default it is a site-to-site client. Return true if successful.
        def create_conn(conn_name, type)
            if @all_conns.has_key? conn_name
                Yast::Popup.Error(_("The connection name is already used."))
                return false
            end
            # Make minimal configuration for the new connection, consists of only a name and scenario
            scenario = type == :gateway ? :gw_psk : :client_psk
            @all_conns[conn_name] = {"name" => conn_name, "scenario" => scenario}
            switch_conn(conn_name)
            return true
        end

        # Modify connection type from client to gateway or the other way around. Return true if successful.
        def change_conn_type(new_type)
            case new_type
            when :gateway
                # Find an unused gateway scenario
                unused_gateway_scenario = ALL_GATEWAY_SCENARIOS.find {|s| find_conn_by_scenario(s).empty?}
                if !unused_gateway_scenario
                    Yast::Popup.Error(_("You may only have one gateway connection per scenario.\n" +
                                        "All of gateway scenarios are already used."))
                    return false
                end
                # Switch connection to the new scenario
                get_current_conn["scenario"] = unused_gateway_scenario
            when :client
                # Switch to client PSK scenario
                get_current_conn["scenario"] = :client_psk
            end
            return true
        end

        # Modify a connection (gateway or client) scenario. Return true if successful.
        def change_scenario(new_scenario)
            # Warn against duplicated configuration
            if get_scenario_conn_type(new_scenario) == :gateway && find_conn_by_scenario(new_scenario).length > 0
                Yast::Popup.Error(_("The scenario is already configured with another gateway.\n" +
                                    "You may not have two gateways operating under one scenario."))
                return false
            end
            # Keep all parameters from the current configuration
            # Because some scenarios can share parameters between each other
            # Unused parameters will be removed automatically before saving configuration
            get_current_conn["scenario"] = new_scenario
            return true
        end

        # Return array of connection names matching the specified connection scenario. Return empty array if none is found.
        def find_conn_by_scenario(scenario_match)
            return @all_conns.select {|name, conf| conf["scenario"] == scenario_match}.keys
        end

        # Return certificate file and key file paths in a tuple, or :nil if there is none.
        def get_gw_cert_and_key
            # Either site2site or Windows client scenario can carry a certificate file
            gw_cert_conn = find_conn_by_scenario(:gw_cert)
            if gw_cert_conn.length == 0
                gw_cert_conn = find_conn_by_scenario(:gw_win)
                if gw_cert_conn.length == 0
                    return nil
                end
            end
            # Key is stored in secrets
            key = @all_secrets[:gw_rsa]
            return [@all_conns[gw_cert_conn[0]]["leftcert"], key]
        end

        # Set gateway certficate and key.
        def set_gw_cert(cert_path, key_path)
            # Gateway scenario uses static keys on both sides
            find_conn_by_scenario(:gw_cert).each{|name|
                @all_conns[name]["leftcert"] = cert_path
                @all_conns[name]["rightcert"] = cert_path
            }
            # Windows clients do not use rightcert
            find_conn_by_scenario(:gw_win).each{|name|
                @all_conns[name]["leftcert"] = cert_path
            }
            @all_secrets[:gw_rsa] = key_path
        end

        # Delete the current connection.
        def del_conn
            del_conn_secrets
            @all_conns.delete(@curr_conn_name)
            @curr_conn_name = @all_conns.length > 0 ? @all_conns.keys[0] : nil
        end

        # Change parameter value for the current connection.
        def change_conn_param(param_name, val)
            if param_name == "right" && (get_current_conn["scenario"] == :client_psk || get_current_conn["scenario"] == :client_cert)
                # Changing gateway IP requires adjusting IPSec secrets
                old_gw_ip = get_current_conn[param_name]
                if get_current_conn["scenario"] == :client_psk
                    psk = @all_secrets[:psk][old_gw_ip]
                    if psk != nil
                        del_conn_secrets
                        @all_secrets[:psk][val] = psk
                    end
                elsif get_current_conn["scenario"] == :client_cert
                    rsa = @all_secrets[:rsa][old_gw_ip]
                    if rsa != nil
                        del_conn_secrets
                        @all_secrets[:rsa][val] = rsa
                    end
                end
            end
            get_current_conn[param_name] = val
            if val == nil
                get_current_conn.delete(param_name)
            end
        end

        # Change gateway password.
        def change_gw_pwd(new_pwd)
            @all_secrets[:gw_psk] = new_pwd
        end

        # Change gateway certificate
        def change_gw_cert(new_cert_path, new_cert_key_path)
            find_conn_by_scenario(:gw_cert).each{|name|
                @all_conns[name]["leftcert"] = new_cert_path
                @all_conns[name]["rightcert"] = new_cert_path
            }
            # Windows clients do not use rightcert
            find_conn_by_scenario(:gw_win).each{|name|
                @all_conns[name]["leftcert"] = new_cert_path
            }
            @all_secrets[:gw_rsa] = new_cert_key_path
        end

        # Create the user (:xauth or :eap). Return true if successful.
        def add_user_pass(type_key, username, password)
            if @all_secrets[type_key].has_key? username
                Yast::Popup.Error(_("The user name is already used."))
                return false
            end
            @all_secrets[type_key][username] = password
            return true
        end

        # Delete the username/password combination from :xauth or :eap secrets.
        def del_user_pass(type_key, username)
            @all_secrets[type_key].delete(username)
        end

        # Delete the password/certificate data specific to the current connection. Affect client connection only.
        def del_conn_secrets
            if get_current_conn["scenario"] == :client_cert
                @all_secrets[:rsa].delete(get_current_conn["right"])
            elsif get_current_conn["scenario"] == :client_psk
                @all_secrets[:psk].delete(get_current_conn["right"])
            end
        end

        # Return all IPSec secrets assorted according to the type.
        def get_all_secrets
            return @all_secrets
        end

        # Return hash of gateway IP vs PSK for all PSK-based client connections.
        def get_client_psks
            Hash[
                @all_conns.select{ |name, conf| conf["right"] != nil && conf["scenario"] == :client_psk}
                           .map{ |name, conf|
                             gw_ip = conf["right"]
                             psk = @all_secrets[:psk][gw_ip]
                             psk = psk == nil ? "" : psk
                             [gw_ip, psk]
                           }
            ]
            # Dangling PSKs are not returned, this is intentional.
        end

        # Return hash of gateway IP vs certificate file for all certificate-based client connections.
        def get_client_certs
            Hash[
                @all_conns.select{ |name, conf| conf["right"] != nil && conf["scenario"] == :client_cert}
                          .map { |name, conf|
                            gw_ip = conf["right"]
                            cert = conf["leftcert"] == nil ? "" : conf["leftcert"] # which is the same as rightcert
                            key = @all_secrets[:rsa][gw_ip]
                            key = key == nil ? "" : key
                            [gw_ip, {:cert => cert, :key => key}]
                          }
            ]
            # Dangling RSA keys are not returned, this is intentional.
        end

        # Set client password (PSK) for a particular connection.
        def set_client_pwd(gateway_ip, new_pwd)
            @all_secrets[:psk][gateway_ip] = new_pwd
        end

        # Set client certificate/key for a connection to remote gateway. Return true if successful, otherwise false.
        def set_client_cert(gateway_ip, cert_path, cert_key_path)
            matching_conn = @all_conns.select{|name, conf| conf["right"] == gateway_ip && conf["scenario"] == :client_cert}
            if matching_conn.length == 0
                Yast::Popup.Error(_("Cannot find a matching client connection."))
                return false
            end
            conn_name = matching_conn.keys[0]
            @all_conns[conn_name]["leftcert"] = cert_path
            @all_conns[conn_name]["rightcert"] = cert_path
            @all_secrets[:rsa][gateway_ip] = cert_key_path
            return true
        end

        # Return tuple of SCR-compatible IPSec connection configuration and connections with incomplete configuration.
        def make_scr_conf
            unfilled_blanks = {} # name VS array of unfilled blanks
            scr_conf = {} # to be returned and fed to SCR backend
            @all_conns.each { |name, conf|
                conn_template = SCENARIO_TEMPLATES[conf["scenario"]]
                # Find customised parameters
                customisation = conf.select{|key, val| conn_template[key] == nil}
                # Merge customised with the template
                merged_conf = conn_template.merge(customisation)
                # Remove parameters that aren't configuration or don't belong to the scenario
                merged_conf.delete("name")
                merged_conf.delete("scenario")
                # Find blanks that aren't filled
                param_blanks = merged_conf.select{|_key, val| val.to_s.strip == ""}.keys
                if param_blanks.any?
                    unfilled_blanks[name] = param_blanks
                end
                scr_conf[name] = merged_conf
            }
            return [scr_conf, unfilled_blanks]
        end

        # Return SCR-compatible IPSec secrets.
        def make_scr_secrets
            scr_secrets = {"psk" => [], "rsa" => [], "eap" => [], "xauth" => []}
            gw_psk = @all_secrets[:gw_psk]
            if gw_psk != ""
                scr_secrets["psk"] += [{"id" => "%any", "secret" => gw_psk}]
            end
            gw_rsa = @all_secrets[:gw_rsa]
            if gw_rsa != ""
                scr_secrets["rsa"] += [{"id" => "%any", "secret" => gw_rsa}]
            end
            scr_secrets["psk"] += @all_secrets[:psk].map{ |id, secret|
                {"id" => id, "secret" => secret}
            }
            scr_secrets["rsa"] += @all_secrets[:rsa].map{ |id, secret|
                {"id" => id, "secret" => secret}
            }
            scr_secrets["xauth"] += @all_secrets[:xauth].map{ |id, secret|
                {"id" => id, "secret" => secret}
            }
            scr_secrets["eap"] += @all_secrets[:eap].map{ |id, secret|
                {"id" => id, "secret" => secret}
            }
            return scr_secrets
        end
    end
    IPSec = IPSecClass.new
end
