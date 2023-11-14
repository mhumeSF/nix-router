{ config, pkgs, ... }:
let
  publicDnsServer = "1.1.1.1";
  vlanNetdev = (name:
    (id: {
      netdevConfig = {
        Name = name;
        Kind = "vlan";
      };
      vlanConfig.Id = id;
    }));
in
{
  imports =
    [ ./hardware-configuration.nix ];

  # Use the systemd-boot EFI boot loader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  boot.kernel.sysctl = {
    "net.ipv4.conf.all.forwarding" = true;
    # Disable IPv6 at the kernel level // will turn on later
    "net.ipv6.conf.all.disable_ipv6" = 1;
    "net.ipv6.conf.default.disable_ipv6" = 1;
    "net.ipv6.conf.lo.disable_ipv6" = 1;
  };

  networking = {
    useDHCP = false;
    useNetworkd = true;
    hostName = "nix-router";

    enableIPv6 = false;
    nameservers = [ "1.1.1.1" "1.0.0.1" ];

    firewall.enable = false;
    nat = {
      enable = true;
      internalInterfaces = [ "lan" ];
      externalInterface = "wan";
    };
    nftables = {
      enable = true;
      ruleset = ''
        table ip filter {
          chain input {
            type filter hook input priority 0; policy drop;

            # Temporary addition, will remove later
            ip saddr 10.0.254.0/24 tcp dport 22 accept

            iifname { "lan" } accept comment "Allow local network to access the router"
            iifname { "lan", "iot", "werk", "guest" } udp dport { 67, 68 } accept comment "Allow DHCP"

            iifname "wan" ct state { established, related } accept comment "Allow established traffic"
            iifname "wan" icmp type { echo-request, destination-unreachable, time-exceeded } counter accept comment "Allow select ICMP"
            iifname "wan" counter drop comment "Drop all other unsolicited traffic from wan"
          }

          chain forward {
            type filter hook forward priority 0; policy drop;

            iifname { "lan", "iot", "werk", "guest" } oifname { "wan" } accept comment "Allow trusted LAN to WAN"
            iifname { "wan" } oifname { "lan", "iot", "werk", "guest" } ct state { established, related } counter accept comment "Allow established back to LANs"

            iifname { "lan" } oifname { "iot" } counter accept comment "Allow trusted LAN to IoT"
            iifname { "iot" } oifname { "lan" } ct state { established, related } counter accept comment "Allow established back to LANs"
          }

          chain output {
            type filter hook output priority 100; policy accept;
          }
        }

        table ip nat {
          chain postrouting {
            type nat hook postrouting priority 100; policy accept;
            oifname "wan" masquerade
          }
        }
      '';
    };
  };

  # SYSTEMD-NETWORKD IS THE NETWORK CONFIGURATION COMPONENT OF THE SYSTEMD
  # SOFTWARE SUITE. IT IS WELL INTEGRATED INTO NIXOS BELOW SYSTEMD.NETWORK AND
  # SHOULD BE PREFERRED OVER NETWORKING.INTERFACES OPTIONS FOR MOST USE CASES,
  # SINCE IT RECEIVES FAR SUPERIOR MAINTENANCE.
  # https://nixos.wiki/wiki/systemd-networkd

  systemd.network = {
    enable = true;

    links = {
      "10-wan" = {
        matchConfig.Path = "pci-0000:00:02.0";
        linkConfig.Name = "wan";
      };
      "10-lan" = {
        matchConfig.Path = "pci-0000:00:08.0";
        linkConfig.Name = "lan";
      };
    };

    netdevs = {
      "20-iot10" = {
        netdevConfig = {
          Kind = "vlan";
          Name = "iot";
        };
        vlanConfig.Id = 110;
      };
      "20-werk20" = {
        netdevConfig = {
          Kind = "vlan";
          Name = "werk";
        };
        vlanConfig.Id = 120;
      };
      "20-guest30" = {
        netdevConfig = {
          Kind = "vlan";
          Name = "guest";
        };
        vlanConfig.Id = 130;
      };
    };

    networks = {
      "10-wan" = {
        matchConfig.Name = "wan";
        networkConfig.DHCP = "ipv4";
      };
      "10-lan" = {
        matchConfig.Name = "lan";
        vlan = [ "iot" "werk" "guest" ];
        address = [ "192.168.100.1/24" ];
        networkConfig = {
          DHCPServer = "yes";
          LinkLocalAddressing = "no";
        };
        linkConfig.MTUBytes = "1512";
        dhcpServerConfig = {
          PoolOffset = 100;
          PoolSize = 141;
          DNS = [ "${publicDnsServer}" ];
        };
      };
      "40-iot" = {
        matchConfig.Name = "iot";
        address = [ "192.168.110.1/24" ];
        networkConfig = {
          DHCPServer = "yes";
        };
        dhcpServerConfig = {
          PoolOffset = 100;
          PoolSize = 141;
          DNS = [ "${publicDnsServer}" ];
        };
      };
      "40-werk" = {
        matchConfig.Name = "werk";
        address = [ "192.168.120.1/24" ];
        networkConfig = {
          DHCPServer = "yes";
        };
        dhcpServerConfig = {
          PoolOffset = 100;
          PoolSize = 141;
          DNS = [ "${publicDnsServer}" ];
        };
      };
      "40-guest" = {
        matchConfig.Name = "guest";
        address = [ "192.168.130.1/24" ];
        networkConfig = {
          DHCPServer = "yes";
        };
        dhcpServerConfig = {
          PoolOffset = 100;
          PoolSize = 141;
          DNS = [ "${publicDnsServer}" ];
        };
      };
    };
  };

  # systemd.services.systemd-networkd.serviceConfig = {
  #   Environment = "SYSTEMD_LOG_LEVEL=debug";
  # };

  time.timeZone = "Pacific/Honolulu";

  environment.systemPackages = with pkgs; [
    usbutils
    pciutils
    htop
    vim
    tcpdump
    ripgrep
    starship
  ];

  security.sudo.wheelNeedsPassword = false;
  users.users = {
    nixie = {
      isNormalUser = true;
      home = "/home/nixie";
      description = "Nixie Admin";
      extraGroups = [ "wheel" ];
      openssh.authorizedKeys.keys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFLpijNKLQTJJXToZRGjRWb2f1EgPG9IzzO85mvbjbaY nixie@router" ];
    };
  };

  programs.zsh.enable = true;
  users.defaultUserShell = pkgs.zsh;

  services = {
    resolved.enable = false;
    openssh.enable = true;
  };

  system.stateVersion = "23.05";

}
