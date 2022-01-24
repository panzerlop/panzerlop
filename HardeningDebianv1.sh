#!/bin/bash -e
#2009 script Copyright (C) 2019  madaidan under GPL
#2022 script Copyright (C) 2022  panzerlop under GPL
#Also shoutout to the Whonix team

#This version is changed to less interupt with daily computing and appropriate for Debian derivitives
#The vast majority of the tweaks are from here
#
#You SHOULD read the information too.
#
#https://theprivacyguide1.github.io/linux_hardening_guide.html 


if [ "$(dpkg -l | awk '/nano/ {print }'|wc -l)" -ge 1 ]; then
  echo You need nano installed for this script
else
  sudo apt-get nano
fi


script_checks() {
 echo ""
  
    if [[ "$(id -u)" -ne 0 ]]; then
      echo "This script needs to be run as root."
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

    # Disable unprivileged user namespaces.
    read -r -p "Disable unprivileged user namespaces? (y/n) " disable_unprivileged_userns
    if [ "${disable_unprivileged_userns}" = "y" ]; then
      echo "kernel.unprivileged_userns_clone=0" > /etc/sysctl.d/unprivileged_users_clone.conf
    fi

    # Disable TCP SACK.
    read -r -p "Disable TCP SACK? (y/n) " disable_sack
    if [ "${disable_sack}" = "y" ]; then
      echo "net.ipv4.tcp_sack=0" > /etc/sysctl.d/tcp_sack.conf
    fi
  fi
}

disable_nf_conntrack_helper() {
 echo ""
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

  # Restricting su to users in the wheel group.
  read -r -p "Restrict su to users in the wheel group? (y/n) " restrict_su
  if [ "${restrict_su}" = "y" ]; then
    # Restricts su by editing files in /etc/pam.d/
    sed -i 's/#auth		required	pam_wheel.so use_uid/auth		required	pam_wheel.so use_uid/' /etc/pam.d/su
    sed -i 's/#auth		required	pam_wheel.so use_uid/auth		required	pam_wheel.so use_uid/' /etc/pam.d/su-l
  fi

  # Lock the root account.
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

firewall() {
  ## Firewall
  read -r -p "Install UFW Firewall (y/n) " install_ufw
  if [ "${install_ufw}" = "y" ]; then
    # Installs ufw if it isn't already.
  read -r -p "Install ufw? [ Firewall ] (y/n) " install_ufw
	if [ "$(dpkg -l | awk '/ufw/ {print }'|wc -l)" -ge 1 ]; then
	echo You need UFW installed for the next part, it should be anyway
	echo ""
	echo It is a simple but effective firewall
	else
    apt-get install firejail
	fi

    # Enable UFW.
    ufw enable
    systemctl enable ufw.service

    # Deny all incoming traffic.
    ufw default deny incoming # Also disables ICMP timestamps
  fi
}

firejail() {
  ## Firewall
  read -r -p "Install Firejail (y/n) " install_firejail
  if [ "${install_firejail}" = "y" ]; then
    # Installs FJ if it isn't already.
  read -r -p "Install Firejail? [ Sandboxing ] (y/n) " install_firejail
	if [ "$(dpkg -l | awk '/firejail/ {print }'|wc -l)" -ge 1 ]; then
    apt-get install firejail
	fi

  fi
}


webcam_and_microphone() {
  ## Block the webcam and microphone.
  read -r -p "Do you want to blacklist the webcam kernel module? (y/n) " blacklist_webcam
  if [ "${blacklist_webcam}" = "y" ]; then
    # Blacklist the webcam kernel module.
    echo "install uvcvideo /bin/true" > /etc/modprobe.d/blacklist-webcam.conf
  fi

  read -r -p "Do you want to blacklist the microphone and speaker kernel module?  (y/n) " blacklist_mic
  if [ "${blacklist_mic}" = "y" ]; then
    # Blacklist the microphone and speaker kernel module.
    mic_modules=$(awk '{print $2}' /proc/asound/modules | awk '!x[$0]++')

    # Accounts for multiple sound cards.
    for i in ${mic_modules}
    do
      echo "install ${i} /bin/true" >> /etc/modprobe.d/blacklist-mic.conf
    done
  fi
}

configure_hostname() {
  ## Change hostname to a generic one.
  read -r -p "Change hostname to 'host'?  (y/n) " hostname
  if [ "${hostname}" = "y" ]; then
    hostnamectl set-hostname host
  fi
}

ending() {
  ## Reboot
  echo ""
  read -r -p "Reboot to apply all the changes? (y/n) " reboot
  if [ "${reboot}" = "y" ]; then
    reboot
  fi
}

echo ""
echo "Security Hardening Script for Debian & derivitives such as Linux Mint"
echo "https://theprivacyguide1.github.io/linux_hardening_guide.html"
echo ""
echo "The vast majority or this script is owed to the information here."
echo "And the bunch of people who've helped with everything."
echo ""
echo ""
read -r -p "Start The Security Hardening Script (y/n) " start
if [ "${start}" = "n" ]; then

echo ""

  exit 1
elif ! [ "${start}" = "y" ]; then
  echo ""
  echo "You did not enter a correct character."
   echo ""
  exit 1
fi

script_checks
sysctl_hardening
firewall
disable_nf_conntrack_helper
restrict_root
firejail
webcam_and_microphone
ending