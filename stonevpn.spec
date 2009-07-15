%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:		stonevpn
Version:	0.4.1
Release:	1%{?dist}
Summary:	Easy OpenVPN certificate and configuration management

Group:		Applications/Internet
License:	GPLv2
URL:		http://sf.net/projects/stonevpn
Source0:	%{name}-%{version}.tar.gz

BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:	noarch

Requires:	python-configobj
Requires:	python-IPy
Requires:	pyOpenSSL
BuildRequires:	python

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
install -D -p -m 0644 stonevpn.conf %{buildroot}/etc/stonevpn.conf.sample

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc COPYING README TODO Changelog
/usr/local/bin/stonevpn
%config /etc/stonevpn.conf.sample

%changelog
* Tue Jul 14 2009 L.S. Keijser <keijser@stone-it.com>
- change the way config file is installed

* Tue May 19 2009 L.S. Keijser <keijser@stone-it.com>
- bumped to version 0.4.1

* Fri Mar 27 2009 L.S. Keijser <keijser@stone-it.com>
- initial release
