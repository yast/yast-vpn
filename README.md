YaST VPN module
=================

[![Workflow Status](https://github.com/yast/yast-vpn/workflows/CI/badge.svg?branch=master)](
https://github.com/yast/yast-vpn/actions?query=branch%3Amaster)
[![OBS](https://github.com/yast/yast-vpn/actions/workflows/submit.yml/badge.svg)](https://github.com/yast/yast-vpn/actions/workflows/submit.yml)

The YaST module manages VPN gateway and client connections for securing site-to-site communication via IPSec VPN.

Features
--------

  * Create gateway for Linux, Android, iOS, and Windows clients.
  * The gateway supports IKEv1 and IKEv2 authentication via X509 certificate, pre-shared key, XAuth, and EAP-MSCHAPv2.
  * Create client connection to a remote Linux gateway.
  * The client connection supports IKEv2 authentication via X509 certificate and pre-shared key.
  * Full IPv6 support.
  * Full AutoYaST support.

Installation
------------

To install the latest stable version, use zypper:

    $ sudo zypper install yast2-vpn

The module is now ready to run:

    $ sudo /usr/sbin/yast2 vpn


Usage
-----
Please visit the following links to openSUSE wiki site for introduction to VPN and the detailed usage instructions of the YaST VPN module:

- [Portal:VPN](https://en.opensuse.org/Portal:VPN)
- [YaST VPN Module](https://en.opensuse.org/Portal:VPN/YaST_VPN_Module)
- [YaST VPN Module Troubleshoot](https://en.opensuse.org/Portal:VPN/YaST_VPN_Module_Troubleshoot)

Legal Warning
------------
Use of encrypted network traffic is illegal in countries where such activities are outlawed. Please observe and comply with advice from your local regulatory authority in regards to network traffic encryption before using the YaST VPN module.

