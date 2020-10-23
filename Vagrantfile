['vagrant-reload'].each do |plugin|
  unless Vagrant.has_plugin?(plugin)
    raise "Vagrant plugin #{plugin} is not installed!"
  end
end

Vagrant.configure('2') do |config|
  config.vm.box = "generic/ubuntu2004" # Ubuntu
  config.vm.network "private_network", ip: "192.168.50.4"

  # fix issues with slow dns https://www.virtualbox.org/ticket/13002
  config.vm.provider :libvirt do |libvirt|
    libvirt.connect_via_ssh = false
    libvirt.memory = 1024
    libvirt.cpus = 2
    libvirt.nic_model_type = "e1000"
  end
  config.vm.synced_folder "./", "/home/vagrant/work"
  config.vm.provision :file, source: "setup-golang.sh", destination: "setup-golang.sh"
  config.vm.provision :shell, :privileged => true, :path => "setup.sh"
  config.vm.provision :shell, :privileged => true, :path => "setup-linux-header.sh"
end
