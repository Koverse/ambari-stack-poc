Name:       hello-world
Version:    1
Release:    1
Summary:    Most simple RPM package
License:    FIXME

%description
This is my first RPM package, which does nothing.

%prep
# we have no source, so nothing here

%build
cat > hello-world.sh <<EOF
#!/usr/bin/bash
echo "This is a sample script to test auto run during boot" > /var/tmp/script.out
echo "The time the script run was -->  `date`" >> /var/tmp/script.out
echo "Hello World"
EOF

cat > hello-world.service <<EOF
# vi /etc/systemd/system/hello-world.service
[Unit]
Description=Description for sample script goes here
After=network.target

[Service]
Type=simple
ExecStart=/var/tmp/hello-world.sh
TimeoutStartSec=0

[Install]
WantedBy=default.target
EOF

%install
mkdir -p %{buildroot}/usr/bin/
install -m 755 hello-world.sh %{buildroot}/usr/bin/hello-world.sh
install -m 755 hello-world.service /etc/systemd/system/hello-world.service

%files
/usr/bin/hello-world.sh

%changelog
# let skip this for now