%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:		stonevpn
Version:	0.4.3
Release:	0%{?dist}
Summary:	Easy OpenVPN certificate and configuration management

Group:		Applications/Internet
License:	GPLv2
URL:		http://sf.net/projects/stonevpn
Source0:	%{name}-%{version}.tar.gz

BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:	noarch

BuildRequires:	python-devel
Requires:	python-configobj python-IPy pyOpenSSL

%description
StoneVPN allows you to manage OpenVPN certificates and create
configurations for Windows and Linux machines based on a
template. It can package everything into a zipfile and mail
it to a user.

%prep
%setup -q 

%build
%{__python} setup.py build

%install
%{__rm} -rf %{buildroot}
%{__python} setup.py install --root %{buildroot}

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc COPYING README TODO Changelog
%dir %{python_sitelib}/StoneVPN
%{python_sitelib}/StoneVPN/app.py*
%{python_sitelib}/StoneVPN/__init__.py*
%{python_sitelib}/%{name}*.egg-info
%{_bindir}/stonevpn
%dir %{_datadir}/StoneVPN
%{_datadir}/StoneVPN/*

%changelog
* Sat Oct 17 2009 L.S. Keijser <keijser@stone-it.com> - 0.4.2-2
- fixed all rpmlint warnings/errors
- cleaned up spec file

* Fri Aug 7 2009 L.S. Keijser <keijser@stone-it.com>
- modify according to new way of installation

* Tue Jul 14 2009 L.S. Keijser <keijser@stone-it.com>
- change the way config file is installed

* Tue May 19 2009 L.S. Keijser <keijser@stone-it.com>
- bumped to version 0.4.1

* Fri Mar 27 2009 L.S. Keijser <keijser@stone-it.com>
- initial release
