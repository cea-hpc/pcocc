%define        __spec_install_post %{nil}
%define          debug_package %{nil}
%define        __os_install_post %{_dbpath}/brp-compress

%{?systemd_requires}
BuildRequires: systemd

Summary: The pcocc guest agent
Name: pcocc-agent
Version: 0.1
Release: 1
License: GPL
Group: Development/Tools
SOURCE0 : %{name}-%{version}.tar.gz
URL: https://github.com/cea-hpc/pcocc-agent

BuildRequires: make

BuildRoot: %{_tmppath}/%{name}-%{version}

%description
%{summary}

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
%make_install

%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
/sbin/*
/etc/systemd/system/*

%changelog


%post
%systemd_post pcocc-agent.service

%preun
%systemd_preun pcocc-agent.service

%postun
%systemd_postun_with_restart pcocc-agent.service


