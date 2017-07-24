package 'dnsmasq'

remote_file "/etc/dnsmasq.conf" do
  owner "root"
  group "root"
  mode "644"
  source "conf/dnsmasq.conf"
end

service "dnsmasq" do
  action :restart
end
