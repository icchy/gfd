package 'dnsmasq'
package 'make'
package 'gcc'

remote_file "/etc/dnsmasq.conf" do
  owner "root"
  group "root"
  mode "644"
  source "conf/dnsmasq.conf"
end

service "dnsmasq" do
  action :restart
end

remote_file "/etc/network/iptables.up.rules" do
  owner "root"
  group "root"
  mode "644"
  source "conf/iptables.up.rules"
end

execute "apply iptables" do
  user "root"
  command "yes | iptables-apply"
end

remote_file "/etc/sysctl.conf" do
  owner "root"
  group "root"
  mode "644"
  source "conf/sysctl.conf"
end

execute "appply sysctl" do
  user "root"
  command "sysctl -p"
end

remote_directory "/home/admin/gfd" do
  action :create
  source "./gfd"
  mode "755"
  owner "admin"
  group "admin"
end

execute "load lkm" do
  user "root"
  cwd "/home/admin/gfd"
  command "make && insmod gfd.ko"
end
