#!/bin/bash -e

#2019 script Copyright (C) 2019  madaidan under GPL
#https://gitlab.com/madaidan/arch-hardening-script
#2022 script panzerlop under GPLv3
#Also shoutout to the Whonix team

# This version is changed to less interupt with daily computing and (mostly) appropriate for Debian derivitives
#
# You SHOULD read the information too.
#
# The vast majority of the tweaks are from here:
# https://theprivacyguide1.github.io/linux_hardening_guide.html 
#
# tested on Ubuntu 21.10 + 22.04
#

set -eu -o pipefail # fail on error and report it, debug all lines



if [ "$(dpkg -l | awk '/nano/ {print }'|wc -l)" -ge 1 ]; then
  echo "You need nano installed for this script"
else
 apt-get -y install nano 
fi

script_checks() {

# !!!!!!!
# not sure about forcing software updates here without a user prompt, could be bad under some scenarios 

 sudo apt-get update
 
 echo ""
      if ! ps -p 1 | grep systemd &>/dev/null; then
      echo "This script can only be used with systemd."
      exit 1
    fi
echo ""
    if [[ "$(id -u)" -ne 0 ]]; then
      echo "This script needs to be run as root. (sudo)"
      exit 1
    fi
}

# It gets a bit heavier now

sysctl_hardening() {
 echo ""
  ## Sysctl
  read -r -p "Harden the kernel with sysctl?(y/n) " sysctl
  if [ "${sysctl}" = "y" ]; then
    # Hide kernel symbols in /proc/kallsyms.
    read -r -p "Hide kernel symbols in /proc/kallsyms? (y/n) " kallsyms
    if [ "${kallsyms}" = "y" ]; then
      echo "kernel.kptr_restrict=2" > /etc/sysctl.d/kptr_restrict.conf
    fi

    # Restrict dmesg to root.
    read -r -p "Restrict dmesg to root only? (y/n) " dmesg
    if [ "${dmesg}" = "y" ]; then
      echo "kernel.dmesg_restrict=1" > /etc/sysctl.d/dmesg_restrict.conf
    fi

    # Harden BPF JIT compiler.
    read -r -p "Harden the BPF JIT compiler? (y/n) " jit
    if [ "${jit}" = "y" ]; then
      echo "kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2" > /etc/sysctl.d/harden_bpf.conf
    fi

    # Restrict ptrace to root.
    read -r -p "Restrict ptrace to root only? (y/n) " ptrace
    if [ "${ptrace}" = "y" ]; then
      echo "kernel.yama.ptrace_scope=2" > /etc/sysctl.d/ptrace_scope.conf
    fi

    # Disable kexec.
    read -r -p "Disable kexec? (y/n) " kexec
    if [ "${kexec}" = "y" ]; then
      echo "kernel.kexec_load_disabled=1" > /etc/sysctl.d/kexec.conf
    fi

    # Harden the TCP/IP stack.
    read -r -p "Harden the TCP/IP stack? (y/n) " tcp_ip_stack_hardening
    if [ "${tcp_ip_stack_hardening}" = "y" ]; then
      # Enable TCP syncookies.
      read -r -p "Enable TCP syncookies? (y/n) " tcp_syncookies
      if [ "${tcp_syncookies}" = "y" ]; then
        echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.d/tcp_hardening.conf
      fi

      # Protect against time-wait assassination.
      read -r -p "Protect against time-wait assassination? (y/n) " tcp_timewait_assassination
      if [ "${tcp_timewait_assassination}" = "y" ]; then
        echo "net.ipv4.tcp_rfc1337=1" >> /etc/sysctl.d/tcp_hardening.conf
      fi

      # Enable reverse path filtering.
      read -r -p "Enable reverse path filtering (rp_filter)? (y/n) " enable_rp_filter
      if [ "${enable_rp_filter}" = "y" ]; then
         echo "net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.d/tcp_hardening.conf
      fi

      # Disable ICMP redirect acceptance.
      read -r -p "Disable ICMP redirect acceptance? (y/n) " disable_icmp_redirect_acceptance
      if [ "${disable_icmp_redirect_acceptance}" = "y" ]; then
        echo "net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.d/tcp_hardening.conf
      fi

      # Disable ICMP redirect sending.
      read -r -p "Disable ICMP redirect sending? (y/n) " disable_icmp_redirect_sending
      if [ "${disable_icmp_redirect_sending}" = "y" ]; then
        echo "net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.d/tcp_hardening.conf
      fi

      # Ignore ICMP requests.
      read -r -p "Ignore ICMP requests? (y/n) " ignore_icmp
      if [ "${ignore_icmp}" = "y" ]; then
        echo "net.ipv4.icmp_echo_ignore_all=1" >> /etc/sysctl.d/tcp_hardening.conf
      fi
    fi

    # Improve ASLR for mmap.
    read -r -p "Improve ASLR effectiveness for mmap? (y/n) " improve_aslr
    if [ "${improve_aslr}" = "y" ]; then
      echo "vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16" > /etc/sysctl.d/mmap_aslr.conf
    fi

    # Disable TCP timestamps
    read -r -p "Disable TCP timestamps? (y/n) " timestamps
    if [ "${timestamps}" = "y" ]; then
      echo "net.ipv4.tcp_timestamps=0" > /etc/sysctl.d/tcp_timestamps.conf
    fi

    # Disable the SysRq key.
    read -r -p "Disable the SysRq key? (y/n) " disable_sysrq
    if [ "${disable_sysrq}" = "y" ]; then
      echo "kernel.sysrq=0" > /etc/sysctl.d/sysrq.conf
    fi


# REMOVED UNTIL FIX FOR FLATPAK DISCOVERED.

    # Disable unprivileged user namespaces.
#    read -r -p "Disable unprivileged user namespaces? THIS MAY BREAK FLATPAKS ( kernel.unprivileged_userns_clone=0 )(y/n) " disable_unprivileged_userns
#    if [ "${disable_unprivileged_userns}" = "y" ]; then
#      echo "kernel.unprivileged_userns_clone=0" > /etc/sysctl.d/unprivileged_users_clone.conf
#    fi

    # Disable TCP SACK.
    read -r -p "Disable TCP SACK? (y/n) " disable_sack
    if [ "${disable_sack}" = "y" ]; then
      echo "net.ipv4.tcp_sack=0" > /etc/sysctl.d/tcp_sack.conf
    fi
  fi
}

disable_nf_conntrack_helper() {

  ## Disable Netfilter connection tracking helper.
  read -r -p "Disable the Netfilter automatic conntrack helper assignment? (y/n) " disable_conntrack_helper
  if [ "${disable_conntrack_helper}" = "y" ]; then
    echo "options nf_conntrack nf_conntrack_helper=0" > /etc/modprobe.d/no-conntrack-helper.conf
  fi
}

restrict_root() {

  ## Restricting root
  # Clear /etc/securetty
 echo ""
  read -r -p "Clear /etc/securetty?  (y/n) " securetty
  if [ "${securetty}" = "y" ]; then
    echo "" > /etc/securetty
  fi

  # Lock the root account - always do this.
  
  read -r -p "Lock the root account?   (y/n) " lock_root_account
  if [ "${lock_root_account}" = "y" ]; then
    passwd -l root
  fi

  # Checks if SSH is installed before asking.
  if [ -x "$(command -v ssh)" ]; then
    # Deny root login via SSH.
    read -r -p "Deny root login via SSH? (y/n) " deny_root_ssh
    if [ "${deny_root_ssh}" = "y" ]; then
      echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
    fi
  fi
}

moreservices() {

  ## Just incase
  read -r -p "Remove more generally un-needed services? (xinetd nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server)  (y/n) " purge_services
  if [ "${purge_services}" = "y" ]; then
		apt-get purge xinetd nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server
  fi
}

firewall() {

  ## Firewall

  read -r -p "Install UFW Firewall and configure it? (y/n) " install_ufw
	  if [ "${install_ufw}" = "y" ]; then

    # Enable UFW.
    ufw enable
    systemctl enable ufw.service

    # Deny all incoming traffic.
    ufw default deny incoming 
    
    # Also disable ICMP timestamps
    sysctl -w net.ipv4.tcp_timestamps=0
    
  fi
}

debsums() {
    # Installs debsums if it isn't already.
  read -r -p "Do you want to install debsums? (y/n) " debsums
  if [ "${debsums}" = "y" ]; then
  
    apt-get -y install debsums 

  fi
}


#    - apt-listbugs                                            [ Not Installed ]
#    - apt-listchanges                                         [ Not Installed ]
#    - checkrestart                                           [[[ outdated or not needed?]]]]
#    - not consistant amongst Debian Distros
#

disable_nf_conntrack_helper() {
  ## Disable Netfilter connection tracking helper.
  read -r -p "Disable the Netfilter automatic conntrack helper assignment? ( y/n)" disable_conntrack_helper
  if [ "${disable_conntrack_helper}" = "y" ]; then
    echo "options nf_conntrack nf_conntrack_helper=0" > /etc/modprobe.d/no-conntrack-helper.conf
  fi
}

#
#
# MAC Randomiser in script soulution would be nice without using curl from 2019 source
#
#

configure_hostname() {
 echo ""
  ## Change hostname to a generic one.
  read -r -p "Change hostname to 'host'?  (y/n) " hostname
  if [ "${hostname}" = "y" ]; then
    hostnamectl set-hostname host
  fi 
}

ending() {
  ## Reboot
  echo ""
   echo " https://github.com/panzerlop/"
   echo ""
   echo "Hope this helped"
   echo "Maybe come improve it?"
    echo ""
       echo ""
  read -r -p "Reboot to apply all the changes? (y/n) " reboot
  if [ "${reboot}" = "y" ]; then
    reboot
  fi
}

echo ""
echo "Security Hardening Script for Debian & derivitives such as Linux Mint"
echo "The vast majority or this script is owed to the information here:"
echo "https://theprivacyguide1.github.io/linux_hardening_guide.html"
echo ""
echo "And the various generosity of some security forums online."
echo ""
echo "You should run debsums after this to check for incorrect package md5 hashes..."
echo ""
cat << "EOF"
               .-.
         .-'``(|||)
      ,`\ \    `-`.
     /   \ '``-.   `
   .-.  ,       `___:
  (:::) :        ___
   `-`  `       ,   :
     \   / ,..-`   ,
      `./ /    .-.`
         `-..-(   ) 
               `-`
EOF

echo ""
echo ""
echo "By using this script you accept any break in system function/ damage / blabla is your own fault..."
echo "So if you also agree with that you may..."
echo ""
read -r -p "...start The Security Hardening Script? (y/n) " start
if [ "${start}" = "n" ]; then

echo ""

  exit 1
elif ! [ "${start}" = "y" ]; then
  echo ""
  echo "You did not enter a correct character."
  echo ""
  echo "Be careful when reading through this script..."
  exit 1
fi

script_checks
sysctl_hardening
firewall
restrict_root
moreservices
configure_hostname
disable_nf_conntrack_helper
debsums
ending
