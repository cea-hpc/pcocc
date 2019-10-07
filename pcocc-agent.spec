%define        __spec_install_post %{nil}
%define          debug_package %{nil}
%define        __os_install_post %{_dbpath}/brp-compress

%{?systemd_requires}
BuildRequires: systemd

Summary: The pcocc guest agent
Name: pcocc-agent
Version: 0.4
Release: 1
License: GPL
Group: Development/Tools
SOURCE0 : %{name}-%{version}.tar.gz
URL: https://github.com/cea-hpc/pcocc/agent


BuildRoot: %{_tmppath}/%{name}-%{version}

%description
%{summary}

%prep

%setup -q

%build
go build .

%install
mkdir -p %{buildroot}/%{_sbindir}
install -m 0755 %{name} %{buildroot}/%{_sbindir}/%{name}
mkdir -p  %{buildroot}/%{_unitdir}
install -m 0644 %{name}.service %{buildroot}/%{_unitdir}/%{name}.service

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_sbindir}/*
%{_unitdir}/*

%changelog


%post
%systemd_post pcocc-agent.service

%preun
%systemd_preun pcocc-agent.service

%postun
%systemd_postun_with_restart pcocc-agent.service


