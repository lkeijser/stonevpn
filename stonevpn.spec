Name:		StoneVPN
Version:	0.4
Release:	1%{?dist}
Summary:	Easy OpenVPN certificate and configuration management

Group:		Applications/Internet
License:	GPLv2
URL:		http://github.com/lkeijser/stonevpn/tree/master
Source0:	stonevpn.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:	noarch
Requires:	python-configobj
Requires:	python-IPy
Requires:	pyOpenSSL

%description
StoneVPN allows you to manage OpenVPN certificates and create
configurations for Windows and Linux machines based on a
template. It can package everything into a zipfile and mail
it to a user.

%prep
%setup -q stonevpn

%build

%install
rm -rf $RPM_BUILD_ROOT
install -D -p -m 0755 stonevpn %{buildroot}/usr/local/bin/stonevpn
install -D -p -m 0644 stonevpn.conf %{buildroot}/etc/stonevpn.conf

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc COPYING README TODO Changelog
/usr/local/bin/stonevpn
/etc/stonevpn.conf

%changelog
* Fri Mar 27 2009 L.S. Keijser <keijser@stone-it.com>
- initial release
