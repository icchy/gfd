# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/trusty64"
  
  config.vm.define "gfd" do |atomic|
    atomic.vm.hostname = "gfd.ictsc"
    atomic.vm.network "private_network", ip: "192.168.18.126", netmask: "255.255.255.128"
    atomic.vm.network "private_network", ip: "192.168.18.129", netmask: "255.255.255.128"
    atomic.vm.provision "shell",
      run: "always",
      inline: <<-SHELL
        apt update
        apt install dnsmasq -y
        cp /vagrant/conf/iptables.up.rules /etc/network/
        yes | iptables-apply
        cp /vagrant/conf/sysctl.conf /etc/
        sysctl -p
        cd /vagrant/gfd && make && insmod gfd.ko && cd -
        ln -fs /vagrant/conf/dnsmasq.conf /etc/dnsmasq.conf
        service dnsmasq restart
      SHELL
  end

  config.vm.define "gfd-client" do |atomic|
    atomic.vm.hostname  = "gfdclient.ictsc"
    atomic.vm.network "private_network", ip: "192.168.18.10", netmask: "255.255.255.128"
    atomic.vm.provision "shell",
      run: "always",
      inline: <<-SHELL
        route del default
        route add default gw 192.168.18.126
        echo nameserver 8.8.8.8 > /etc/resolv.conf
      SHELL
  end

  config.vm.define "gfd-vpn" do |atomic|
    atomic.vm.hostname = "gfdvpn.ictsc"
    atomic.vm.network "private_network", ip: "192.168.18.130", netmask: "255.255.255.128"
  end
end
