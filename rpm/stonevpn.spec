%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:		stonevpn
Version:	0.4.5
Release:	2%{?dist}
Summary:	Easy OpenVPN certificate and configuration management

Group:		Applications/Internet
License:	GPLv2+
URL:		http://github.com/lkeijser/stonevpn
Source0:	http://cloud.github.com/downloads/lkeijser/%{name}/%{name}-%{version}.tar.gz

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
#mkdir %{buildroot}/%{_mandir}
mkdir -p %{buildroot}/%{_mandir}/man{1,5}
install -m 644 man/stonevpn.1 %{buildroot}/%{_mandir}/man1/
install -m 644 man/stonevpn.conf.5 %{buildroot}/%{_mandir}/man5/

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc COPYING README TODO Changelog
%dir %{python_sitelib}/StoneVPN
%{python_sitelib}/StoneVPN/app.py*
%{python_sitelib}/StoneVPN/__init__.py*
%if 0%{?fedora}
%{python_sitelib}/%{name}*.egg-info
%endif
%{_bindir}/stonevpn
%config(noreplace) %{_sysconfdir}/%{name}.conf
%{_mandir}/man1/%{name}.*
%{_mandir}/man5/%{name}.*

%changelog
* Wed Feb 03 2010 L.S. Keijser <keijser@stone-it.com> - 0.4.5-2
- typo in branch tag in files section

* Tue Feb 02 2010 L.S. Keijser <keijser@stone-it.com> - 0.4.5-1
- new version from upstream

* Mon Nov 09 2009 L.S. Keijser <keijser@stone-it.com> - 0.4.4-1
- new version from upstream

* Fri Nov 06 2009 L.S. Keijser <keijser@stone-it.com> - 0.4.3-2
- _really_ removed unnecessary files residing in /usr/share/StoneVPN

* Fri Nov 06 2009 L.S. Keijser <keijser@stone-it.com> - 0.4.3-1
- fixed EVR: now set to 1 (Fedora standard)
- fixed license tag
- fixed SourceURL
- removed unnecessary files (specfile, patches and license files)
- ensure /etc/stonevpn.conf is present after installation

* Thu Oct 22 2009 L.S. Keijser <keijser@stone-it.com> - 0.4.3-0
- changed for Fedora packaging release testing

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
