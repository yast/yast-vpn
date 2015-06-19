#!/usr/bin/env rspec

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
# Summary: Test the functions and features of IPSec configuration agents.
# Authors: Howard Guo <hguo@suse.com>

ENV["Y2DIR"] = File.expand_path("../../src", __FILE__)

require "pp"
require "yast"
require "yast/rspec"

describe Yast::IPSecConf do
    before(:all) do
        change_scr_root(File.expand_path("../chroot", __FILE__))
        # Load IPSec connections and secrets from test case data
        Yast::IPSecConf.Read
    end
    after(:all) do
        reset_scr_root
    end

    it "Reads and parses ipsec.conf and ipsec.secrets" do
        expect(Yast::IPSecConf.GetDeserialisedIPSecConf["value"].length).to be > 3
        expect(Yast::IPSecConf.GetDeserialisedIPSecSecrets["value"].length).to be > 3
    end

    it "Loads IPSec connection configuration and re-import" do
        match = {
            "l2tp"=>{"type"=>"transport", "keyexchange"=>"ikev1", "authby"=>"psk"},
            "ikev1"=>
                {"keyexchange"=>"ikev1",
                "rightsourceip"=>"192.168.84.0/24",
                "xauth"=>"server",
                "authby"=>"xauthpsk"},
            "windows"=>
                {"keyexchange"=>"ikev2",
                "rightsourceip"=>"192.168.85.0/24",
                "ike"=>"aes256-sha1-modp1024!",
                "esp"=>"aes256-sha1!",
                "leftauth"=>"pubkey",
                "leftcert"=>"/hg/hg.crt",
                "right"=>"%any",
                "rightauth"=>"eap-mschapv2",
                "rightsendcert"=>"never",
                "eap_identity"=>"%any"},
            "gw_psk0"=>
                {"auto"=>"add",
                "keyexchange"=>"ikev2",
                "left"=>"%defaultroute",
                "leftauth"=>"psk",
                "leftsubnet"=>"192.168.82.0/24",
                "rightsourceip"=>"192.168.83.0/24",
                "right"=>"%any",
                "rightauth"=>"psk",
                "fragmentation"=>"yes",
                "dpdaction"=>"clear",
                "dpdtimeout"=>"600",
                "dpddelay"=>"60"},
            "gw_cert1"=>
                {"auto"=>"add",
                "keyexchange"=>"ikev2",
                "left"=>"%defaultroute",
                "leftcert"=>"/gw.crt",
                "leftauth"=>"pubkey",
                "leftsubnet"=>"0.0.0.0/0",
                "rightsourceip"=>"192.168.83.0/24",
                "right"=>"%any",
                "rightcert"=>"/gw.crt",
                "rightauth"=>"pubkey",
                "fragmentation"=>"yes",
                "dpdaction"=>"clear",
                "dpdtimeout"=>"600",
                "dpddelay"=>"60"},
            "gw_mobile2"=>
                {"auto"=>"add",
                "keyexchange"=>"ikev1",
                "left"=>"%defaultroute",
                "leftauth"=>"psk",
                "leftsubnet"=>"0.0.0.0/0",
                "rightsourceip"=>"192.168.98.0/24",
                "right"=>"%any",
                "rightauth"=>"psk",
                "rightauth2"=>"xauth",
                "fragmentation"=>"yes",
                "dpdaction"=>"clear",
                "dpdtimeout"=>"600",
                "dpddelay"=>"60"},
            "gw_win3"=>
                {"auto"=>"add",
                "keyexchange"=>"ikev2",
                "rekey"=>"no",
                "left"=>"%defaultroute",
                "leftcert"=>"/ipsec.crt",
                "leftauth"=>"pubkey",
                "leftsubnet"=>"0.0.0.0/0",
                "right"=>"%any",
                "rightsendcert"=>"never",
                "rightauth"=>"eap-mschapv2",
                "eap_identity"=>"%any",
                "esp"=>"aes256-sha1!",
                "ike"=>"aes256-sha1-modp1024!",
                "rightsourceip"=>"192.168.99.0/24",
                "fragmentation"=>"yes",
                "dpdaction"=>"clear",
                "dpdtimeout"=>"600",
                "dpddelay"=>"60"},
            "client_psk4"=>
                {"auto"=>"start",
                "keyexchange"=>"ikev2",
                "left"=>"%defaultroute",
                "leftsourceip"=>"%config",
                "leftauth"=>"psk",
                "right"=>"192.168.122.123",
                "rightauth"=>"psk",
                "rightsubnet"=>"192.168.100.0/24",
                "fragmentation"=>"yes",
                "dpdtimeout"=>"600",
                "dpddelay"=>"60",
                "dpdaction" => "restart",
                "closeaction" => "restart",
                "keyingtries" => "%forever"},
            "client_cert5"=>
                {"auto"=>"start",
                 "keyexchange"=>"ikev2",
                 "left"=>"%defaultroute",
                 "leftcert"=>"/gw.crt",
                 "leftauth"=>"pubkey",
                 "leftsourceip"=>"%config",
                 "right"=>"192.168.122.124",
                 "rightsubnet"=>"192.168.101.0/24",
                 "rightcert"=>"/gw.crt",
                 "rightauth"=>"pubkey",
                 "fragmentation"=>"yes",
                 "dpdtimeout"=>"600",
                 "dpddelay"=>"60",
                 "dpdaction" => "restart",
                 "closeaction" => "restart",
                 "keyingtries" => "%forever"}
        }
        expect(Yast::IPSecConf.GetIPSecConnections).to eq(match)
        Yast::IPSecConf.Import(Yast::IPSecConf.Export)
        expect(Yast::IPSecConf.GetIPSecConnections).to eq(match)
    end

    it "Loads IPSec secrets" do
        match = {
            "psk" =>
                [{"id"=>"", "secret"=>"aaa"},
                 {"id"=>"", "secret"=>"bbb"},
                 {"id"=>"127.0.0.1", "secret"=>"ccc"},
                 {"id"=>"192.168.122.123", "secret"=>"ddd"},
                 {"id"=>"%any 25.52.34.34", "secret"=>"test123"},
                 {"id"=>"2620:113:80c0:8080:9a90:96ff:fea9:c584", "secret"=>"ipv6"}],
            "rsa"=>
                [{"id"=>"", "secret"=>"/key1.pem"},
                 {"id"=>"", "secret"=>"/key2.pem"},
                 {"id"=>"8.8.4.4", "secret"=>"/key3.pem"},
                 {"id"=>"8.8.8.8", "secret"=>"/key4.pem"},
                 {"id"=>"192.168.122.124", "secret"=>"/key5.pem"}],
            "eap"=>
                [{"id"=>"user4", "secret"=>"ea"},
                 {"id"=>"user5", "secret"=>"eb"},
                 {"id"=>"", "secret"=>"ec"}],
            "xauth"=>
                [{"id"=>"user1", "secret"=>"xa"},
                 {"id"=>"user2", "secret"=>"xb"},
                 {"id"=>"", "secret"=>"xc"}]
        }
        expect(Yast::IPSecConf.GetIPSecSecrets).to eq(match)
        Yast::IPSecConf.Import(Yast::IPSecConf.Export)
        expect(Yast::IPSecConf.GetIPSecSecrets).to eq(match)
    end

    it "Identifies unsupported connection configuration" do
        expect(Yast::IPSecConf.GetUnsupportedConfiguration).to eq(["config setup", "conn %default"])
    end

    it "Identifies unsupported key configuration" do
        expect(Yast::IPSecConf.GetUnsupportedSecrets).to eq(["PIN", "def PIN"])
    end

    it "Makes firewall script" do
        exported = Yast::IPSecConf.Export
        exported["tcp_mss_1024"] = true
        Yast::IPSecConf.Import(exported)
        expect(Yast::IPSecConf.GenFirewallScript).to eq("""# The file is automatically generated by YaST VPN module.
# You may run the file using bourne-shell-compatible interpreter.
fw_custom_after_chain_creation() {
iptables -A INPUT -p udp --dport 500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT
ip6tables -A INPUT -p udp --dport 500 -j ACCEPT
ip6tables -A INPUT -p udp --dport 4500 -j ACCEPT
iptables -A INPUT -p 50 -j ACCEPT
ip6tables -A INPUT -p 50 -j ACCEPT
true
}
fw_custom_after_chain_creation
fw_custom_before_port_handling() {
true
}
fw_custom_before_port_handling
fw_custom_before_masq() {
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1024
ip6tables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1024
iptables -A FORWARD -s 192.168.83.0/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.83.0/24 -j MASQUERADE
iptables -A FORWARD -s 192.168.98.0/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.98.0/24 -j MASQUERADE
iptables -A FORWARD -s 192.168.99.0/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.99.0/24 -j MASQUERADE
true
}
fw_custom_before_masq
fw_custom_before_denyall() {
true
}
fw_custom_before_denyall
fw_custom_after_finished() {
true
}
fw_custom_after_finished
""")
    end
end