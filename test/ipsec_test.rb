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
# Summary: Test the functions and features of IPSec configuration models.
# Authors: Howard Guo <hguo@suse.com>

ENV["Y2DIR"] = File.expand_path("../../src", __FILE__)

require "pp"
require "yast"
require "yast/rspec"
require "vpn/ipsec"

describe VPN::IPSec do
    before(:all) do
        # Load IPSec connections and secrets from test case data
        change_scr_root(File.expand_path("../chroot", __FILE__))
    end
    after(:all) do
        reset_scr_root
    end

    it "Loads configuration and secrets model" do
        Yast::IPSecConf.Read
        VPN::IPSec.reload
        expect(VPN::IPSec.get_all_conns).to eq(
            {"gw_psk0"=>
                {"name"=>"gw_psk0",
                "scenario"=>:gw_psk,
                "leftsubnet"=>"192.168.82.0/24",
                "rightsourceip"=>"192.168.83.0/24"},
            "gw_cert1"=>
                {"name"=>"gw_cert1",
                "scenario"=>:gw_cert,
                "leftcert"=>"/gw.crt",
                "rightcert"=>"/gw.crt",
                "leftsubnet"=>"0.0.0.0/0",
                "rightsourceip"=>"192.168.83.0/24"},
            "gw_mobile2"=>
                {"name"=>"gw_mobile2",
                "scenario"=>:gw_mobile,
                "leftsubnet"=>"0.0.0.0/0",
                "rightsourceip"=>"192.168.98.0/24"},
            "gw_win3"=>
                {"name"=>"gw_win3",
                "scenario"=>:gw_win,
                "leftcert"=>"/ipsec.crt",
                "leftsubnet"=>"0.0.0.0/0",
                "rightsourceip"=>"192.168.99.0/24"},
            "client_psk4"=>
                {"name"=>"client_psk4",
                "scenario"=>:client_psk,
                "right"=>"192.168.122.123",
                "rightsubnet"=>"192.168.100.0/24"},
            "client_cert5"=>
                {"name"=>"client_cert5",
                "scenario"=>:client_cert,
                "leftcert"=>"/gw.crt",
                "right"=>"192.168.122.124",
                "rightcert"=>"/gw.crt",
                "rightsubnet"=>"192.168.101.0/24"}
        })
    end

    it "Identifies connection type from scenario" do
        expect(VPN::IPSec.get_scenario_conn_type(:gw_psk)).to eq(:gateway)
        expect(VPN::IPSec.get_scenario_conn_type(:gw_win)).to eq(:gateway)
        expect(VPN::IPSec.get_scenario_conn_type(:client_cert)).to eq(:client)
    end

    it "Switches to other connections" do
        expect(VPN::IPSec.get_current_conn).to eq({
            "name"=>"gw_psk0",
            "scenario"=>:gw_psk,
            "leftsubnet"=>"192.168.82.0/24",
            "rightsourceip"=>"192.168.83.0/24"
        })
        expect(VPN::IPSec.get_current_conn_type).to eq(:gateway)
        VPN::IPSec.switch_conn("client_psk4")
        expect(VPN::IPSec.get_current_conn).to eq({
            "name"=>"client_psk4",
            "scenario"=>:client_psk,
            "right"=>"192.168.122.123",
            "rightsubnet"=>"192.168.100.0/24"
        })
        expect(VPN::IPSec.get_current_conn_type).to eq(:client)
    end

    it "Creates both gateway and client connections" do
        expect(VPN::IPSec.create_conn("NewClient", :client)).to eq(true)
        expect(VPN::IPSec.get_current_conn_type).to eq(:client)
        expect(VPN::IPSec.get_current_conn).to eq({
            "name"=>"NewClient",
            "scenario"=>:client_psk
        })
        expect(VPN::IPSec.create_conn("NewGateway", :gateway)).to eq(true)
        expect(VPN::IPSec.get_current_conn_type).to eq(:gateway)
        expect(VPN::IPSec.get_current_conn).to eq({
            "name"=>"NewGateway",
            "scenario"=>:gw_psk
        })
        expect(VPN::IPSec.create_conn("NewGateway", :gateway)).to eq(false)
    end

    it "Changes connection type from gateway to client and the other way around" do
        VPN::IPSec.switch_conn("NewClient")
        expect(VPN::IPSec.change_conn_type(:gateway)).to eq(false)
        VPN::IPSec.switch_conn("NewGateway")
        expect(VPN::IPSec.change_conn_type(:client)).to eq(true)
        # free up a gateway scenario so that NewClient can become gateway
        VPN::IPSec.switch_conn("gw_win3")
        VPN::IPSec.del_conn
        VPN::IPSec.switch_conn("NewClient")
        expect(VPN::IPSec.change_conn_type(:gateway)).to eq(true)
    end

    it "Deletes gateway and client connections" do
        VPN::IPSec.switch_conn("NewClient")
        VPN::IPSec.del_conn
        expect(VPN::IPSec.get_current_conn).to eq({
            "name"=>"gw_psk0",
            "scenario"=>:gw_psk,
            "leftsubnet"=>"192.168.82.0/24",
            "rightsourceip"=>"192.168.83.0/24"
        })
        VPN::IPSec.switch_conn("NewGateway")
        VPN::IPSec.del_conn
        expect(VPN::IPSec.get_current_conn).to eq({
            "name"=>"gw_psk0",
            "scenario"=>:gw_psk,
            "leftsubnet"=>"192.168.82.0/24",
            "rightsourceip"=>"192.168.83.0/24"
        })
        VPN::IPSec.switch_conn("NewGateway")
        expect(VPN::IPSec.get_current_conn).to eq(nil)
        VPN::IPSec.switch_conn("gw_mobile2")
        VPN::IPSec.del_conn
        expect(VPN::IPSec.get_all_conns.keys).to eq(["gw_psk0", "gw_cert1", "client_psk4", "client_cert5"])
    end

    it "Changes connection parameter and gateway IP" do
        VPN::IPSec.switch_conn("client_psk4")
        expect(VPN::IPSec.get_current_conn).to eq({"name"=>"client_psk4",
            "scenario"=>:client_psk,
            "right"=>"192.168.122.123",
            "rightsubnet"=>"192.168.100.0/24"})
        VPN::IPSec.change_conn_param("right", "1.1.1.1")
        VPN::IPSec.change_conn_param("rightsubnet", "10.0.0.0/8")
        expect(VPN::IPSec.get_current_conn).to eq({"name"=>"client_psk4",
            "scenario"=>:client_psk,
            "right"=>"1.1.1.1",
            "rightsubnet"=>"10.0.0.0/8"})
        expect(VPN::IPSec.get_client_psks["1.1.1.1"]).to eq("ddd")
        expect(VPN::IPSec.get_client_psks["192.168.122.123"]).to eq(nil)
    end

    it "Loads all supported connection secrets" do
        expect(VPN::IPSec.get_all_secrets).to eq({
            :xauth=>{"user1"=>"xa", "user2"=>"xb", ""=>"xc"},
            :eap=>{"user4"=>"ea", "user5"=>"eb", ""=>"ec"},
            :psk=>{"127.0.0.1"=>"ccc", "1.1.1.1"=>"ddd", "%any 25.52.34.34"=>"test123",
                   "2620:113:80c0:8080:9a90:96ff:fea9:c584"=>"ipv6"},
            :gw_psk=>"bbb",
            :rsa=>{"8.8.4.4"=>"/key3.pem", "8.8.8.8"=>"/key4.pem", "192.168.122.124"=>"/key5.pem"},
            :gw_rsa=>"/key2.pem"})
    end

    it "Load and set gateway credentials" do
        # PSK
        expect(VPN::IPSec.get_all_secrets[:gw_psk]).to eq("bbb")
        VPN::IPSec.get_all_secrets[:gw_psk] = "ccc"
        expect(VPN::IPSec.get_all_secrets[:gw_psk]).to eq("ccc")
        # Certificate
        expect(VPN::IPSec.get_gw_cert_and_key).to eq(["/gw.crt", "/key2.pem"])
        VPN::IPSec.set_gw_cert("/abc.crt", "/abc.key")
        expect(VPN::IPSec.get_gw_cert_and_key).to eq(["/abc.crt", "/abc.key"])
    end

    it "Creates and deletes EAP/XAuth users" do
        expect(VPN::IPSec.add_user_pass(:eap, "test1", "pwd1")).to eq(true)
        expect(VPN::IPSec.add_user_pass(:eap, "test1", "pwd1")).to eq(false)
        expect(VPN::IPSec.add_user_pass(:xauth, "test1", "pwd1")).to eq(true)
        expect(VPN::IPSec.add_user_pass(:xauth, "test1", "pwd1")).to eq(false)
        expect(VPN::IPSec.get_all_secrets[:xauth]).to eq ({"user1"=>"xa", "user2"=>"xb", ""=>"xc", "test1"=>"pwd1"})
        expect(VPN::IPSec.get_all_secrets[:eap]).to eq ({"user4"=>"ea", "user5"=>"eb", ""=>"ec", "test1"=>"pwd1"})
    end

    it "Creates and deletes client PSK and certificates" do
        # Create PSK client and assign password
        expect(VPN::IPSec.create_conn("PSKClient", :client)).to eq(true)
        VPN::IPSec.change_conn_param("right", "10.0.0.1")
        VPN::IPSec.change_conn_param("rightsubnet", "0.0.0.0/0")
        VPN::IPSec.change_scenario(:client_psk)
        expect(VPN::IPSec.get_current_conn).to eq({
            "name"=>"PSKClient",
            "scenario"=>:client_psk,
            "rightsubnet"=>"0.0.0.0/0",
            "right"=>"10.0.0.1"
        })
        expect(VPN::IPSec.get_client_psks).to eq({"1.1.1.1"=>"ddd", "10.0.0.1"=>""})
        VPN::IPSec.set_client_pwd("10.0.0.1", "newpass")
        expect(VPN::IPSec.get_client_psks).to eq({"1.1.1.1"=>"ddd", "10.0.0.1"=>"newpass"})

        # Create certificate client and assign certificate
        expect(VPN::IPSec.create_conn("CertClient", :client)).to eq(true)
        VPN::IPSec.change_conn_param("right", "10.0.0.2")
        VPN::IPSec.change_conn_param("rightsubnet", "0.0.0.0/0")
        VPN::IPSec.change_scenario(:client_cert)
        expect(VPN::IPSec.get_current_conn).to eq({
            "name"=>"CertClient",
            "scenario"=>:client_cert,
            "rightsubnet"=>"0.0.0.0/0",
            "right"=>"10.0.0.2"
        })
         expect(VPN::IPSec.get_client_certs).to eq({
            "192.168.122.124"=>{:cert=>"/gw.crt", :key=>"/key5.pem"},
            "10.0.0.2"=>{:cert=>"", :key=>""}
        })
         expect(VPN::IPSec.set_client_cert("10.0.0.2", "/crt", "/key")).to eq(true)
         expect(VPN::IPSec.set_client_cert("10.0.0.3", "/crt", "/key")).to eq(false)
         expect(VPN::IPSec.get_client_certs).to eq({
            "192.168.122.124"=>{:cert=>"/gw.crt", :key=>"/key5.pem"},
            "10.0.0.2"=>{:cert=>"/crt", :key=>"/key"}
        })

         # Delete client connections should also delete associated secrets
         VPN::IPSec.switch_conn("PSKClient")
         VPN::IPSec.del_conn
         expect(VPN::IPSec.get_all_secrets).to eq({
            :xauth=>{"user1"=>"xa", "user2"=>"xb", ""=>"xc", "test1"=>"pwd1"},
            :eap=>{"user4"=>"ea", "user5"=>"eb", ""=>"ec", "test1"=>"pwd1"},
            :psk => {"127.0.0.1"=>"ccc", "%any 25.52.34.34"=>"test123", "1.1.1.1"=>"ddd",
                     "2620:113:80c0:8080:9a90:96ff:fea9:c584"=>"ipv6"},
            :gw_psk=>"ccc",
            :rsa=>{"8.8.4.4"=>"/key3.pem", "8.8.8.8"=>"/key4.pem", "192.168.122.124"=>"/key5.pem", "10.0.0.2"=>"/key"},
            :gw_rsa=>"/abc.key"
        })
         VPN::IPSec.switch_conn("CertClient")
         VPN::IPSec.del_conn
         expect(VPN::IPSec.get_all_secrets).to eq({
            :xauth=>{"user1"=>"xa", "user2"=>"xb", ""=>"xc", "test1"=>"pwd1"},
            :eap=>{"user4"=>"ea", "user5"=>"eb", ""=>"ec", "test1"=>"pwd1"},
            :psk=>{"127.0.0.1"=>"ccc", "1.1.1.1"=>"ddd", "%any 25.52.34.34"=>"test123",
                   "2620:113:80c0:8080:9a90:96ff:fea9:c584"=>"ipv6"},
            :gw_psk=>"ccc",
            :rsa=>{"8.8.4.4"=>"/key3.pem", "8.8.8.8"=>"/key4.pem", "192.168.122.124"=>"/key5.pem"},
            :gw_rsa=>"/abc.key"
        })
    end

    it "Keeps client certificate after changing gateway IP" do
        expect(VPN::IPSec.create_conn("CertClient", :client)).to eq(true)
        VPN::IPSec.change_conn_param("right", "10.0.0.2")
        VPN::IPSec.change_scenario(:client_cert)
        expect(VPN::IPSec.set_client_cert("10.0.0.2", "/crt", "/key")).to eq(true)
        VPN::IPSec.change_conn_param("right", "10.0.0.3")
        expect(VPN::IPSec.get_all_secrets).to eq({
            :xauth=>{"user1"=>"xa", "user2"=>"xb", ""=>"xc", "test1"=>"pwd1"},
            :eap=>{"user4"=>"ea", "user5"=>"eb", ""=>"ec", "test1"=>"pwd1"},
            :psk=>{"127.0.0.1"=>"ccc", "1.1.1.1"=>"ddd", "%any 25.52.34.34"=>"test123",
                   "2620:113:80c0:8080:9a90:96ff:fea9:c584"=>"ipv6"},
            :gw_psk=>"ccc",
            :rsa=>{"10.0.0.3" => "/key", "8.8.4.4"=>"/key3.pem", "8.8.8.8"=>"/key4.pem", "192.168.122.124"=>"/key5.pem"},
            :gw_rsa=>"/abc.key"
        })
         VPN::IPSec.switch_conn("CertClient")
         VPN::IPSec.del_conn
    end

    it "Makes SCR-compatible IPSec config and secrets" do
        # Introduce unnecessary parameters, make_scr_conf will get rid of these
        VPN::IPSec.switch_conn("gw_psk0")
        VPN::IPSec.change_conn_param("abc", 123)
        VPN::IPSec.switch_conn("gw_cert1")
        VPN::IPSec.change_conn_param("bcd", nil)

        scr_conf, unfilled_blanks = VPN::IPSec.make_scr_conf
        expect(scr_conf).to eq({
        "gw_psk0"=>
            {"auto"=>"add",
            "keyexchange"=>"ikev2",
            "left"=>"%defaultroute",
            "leftauth"=>"psk",
            "right"=>"%any",
            "rightauth"=>"psk",
            "fragmentation"=>"yes",
            "dpdaction"=>"clear",
            "dpdtimeout"=>"600",
            "dpddelay"=>"60",
            "leftsubnet"=>"192.168.82.0/24",
            "rightsourceip"=>"192.168.83.0/24"},
        "gw_cert1"=>
            {"auto"=>"add",
            "keyexchange"=>"ikev2",
            "left"=>"%defaultroute",
            "leftauth"=>"pubkey",
            "right"=>"%any",
            "rightauth"=>"pubkey",
            "fragmentation"=>"yes",
            "dpdaction"=>"clear",
            "dpdtimeout"=>"600",
            "dpddelay"=>"60",
            "leftcert"=>"/abc.crt",
            "rightcert"=>"/abc.crt",
            "leftsubnet"=>"0.0.0.0/0",
            "rightsourceip"=>"192.168.83.0/24"},
        "client_psk4"=>
            {"auto"=>"start",
            "keyexchange"=>"ikev2",
            "left"=>"%defaultroute",
            "leftauth"=>"psk",
            "leftsourceip"=>"%config",
            "rightauth"=>"psk",
            "fragmentation"=>"yes",
            "dpdtimeout"=>"600",
            "dpddelay"=>"60",
            "right"=>"1.1.1.1",
            "dpdaction" => "restart",
            "closeaction" => "restart",
            "keyingtries" => "%forever",
            "rightsubnet"=>"10.0.0.0/8"},
        "client_cert5"=>
            {"auto"=>"start",
            "keyexchange"=>"ikev2",
            "left"=>"%defaultroute",
            "leftsourceip"=>"%config",
            "leftauth"=>"pubkey",
            "rightauth"=>"pubkey",
            "fragmentation"=>"yes",
            "dpdtimeout"=>"600",
            "dpddelay"=>"60",
            "leftcert"=>"/gw.crt",
            "right"=>"192.168.122.124",
            "rightcert"=>"/gw.crt",
            "dpdaction" => "restart",
            "closeaction" => "restart",
            "keyingtries" => "%forever",
            "rightsubnet"=>"192.168.101.0/24"}})
        expect(unfilled_blanks).to eq({})

        # Empty some important parameters
        VPN::IPSec.switch_conn("client_cert5")
        VPN::IPSec.change_conn_param("leftcert", "  ")
        VPN::IPSec.switch_conn("gw_cert1")
        VPN::IPSec.change_conn_param("rightsourceip", nil)
        _, unfilled_blanks = VPN::IPSec.make_scr_conf
        expect(unfilled_blanks).to eq({"gw_cert1"=>["rightsourceip"], "client_cert5"=>["leftcert"]})

        # Test making of IPSec secrets
        expect(VPN::IPSec.make_scr_secrets).to eq({
        "psk"=>
            [{"id"=>"%any", "secret"=>"ccc"},
            {"id"=>"127.0.0.1", "secret"=>"ccc"},
            {"id"=>"%any 25.52.34.34", "secret"=>"test123"},
            {"id"=>"2620:113:80c0:8080:9a90:96ff:fea9:c584", "secret"=>"ipv6"},
            {"id"=>"1.1.1.1", "secret"=>"ddd"}],
        "rsa"=>
            [{"id"=>"%any", "secret"=>"/abc.key"},
            {"id"=>"8.8.4.4", "secret"=>"/key3.pem"},
            {"id"=>"8.8.8.8", "secret"=>"/key4.pem"},
            {"id"=>"192.168.122.124", "secret"=>"/key5.pem"}],
        "eap"=>
            [{"id"=>"user4", "secret"=>"ea"},
            {"id"=>"user5", "secret"=>"eb"},
            {"id"=>"", "secret"=>"ec"},
            {"id"=>"test1", "secret"=>"pwd1"}],
        "xauth"=>
            [{"id"=>"user1", "secret"=>"xa"},
            {"id"=>"user2", "secret"=>"xb"},
            {"id"=>"", "secret"=>"xc"},
            {"id"=>"test1", "secret"=>"pwd1"}]})
    end
end
