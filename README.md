YaST VPN module
=================

[![Travis Build](https://travis-ci.org/yast/yast-vpn.svg?branch=master)](https://travis-ci.org/yast/yast-vpn)
[![Jenkins Build](http://img.shields.io/jenkins/s/https/ci.opensuse.org/yast-vpn-master.svg)](https://ci.opensuse.org/view/Yast/job/yast-vpn-master/)

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

Legal Warning
------------
Use of encrypted network traffic is illegal in countries where such activities are outlawed. Please observe and comply with advice from your local regulatory authority in regards to network traffic encryption before using the YaST VPN module.

