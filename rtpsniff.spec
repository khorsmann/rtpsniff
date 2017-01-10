Name:		rtpsniff
Version:	1.0.0
Release:	3%{?dist}
Summary:	rtpsniff
Group:	        Networking/Utilities
License:	GPLv3
URL:		https://github.com/lmangani/rtpsniff
Source0:	https://github.com/lmangani/rtpsniff/archive/master.zip
Source1:	rtpsniff.init
Source2:	rtpsniff.logrotate
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires:  make, unzip, libtool, gcc
Requires:	logrotate
Obsoletes: 	rtpsniff <= %{version}
Provides: 	rtpsniff = %{version}
Conflicts: 	rtpsniff < %{version}

%description
RTPSniff is a tool to sniff RTP traffic and show stats about it.

%prep
%setup -q -n %{name}-master

%build
make MOD_OUT=out_json

%install
rm -rf %{buildroot}
make install PREFIX=%{buildroot}/usr/local

install -d %{buildroot}/etc/init.d
install -d %{buildroot}/etc/logrotate.d

cp %{SOURCE1} %{buildroot}/etc/init.d/rtpsniff
cp %{SOURCE2} %{buildroot}/etc/logrotate.d/rtpsniff

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig /usr/local/lib/

%postun
/sbin/ldconfig /usr/local/lib/

%preun

%files
%attr(644,root,root)/usr/local/lib/libslowpoll.so
%attr(755,root,root)/usr/local/sbin/rtpsniff
%attr(755,root,root)/etc/init.d/rtpsniff
%attr(644,root,root)/etc/logrotate.d/rtpsniff
%defattr(-,root,root,-)
%doc

%changelog
* Mon Jan 09 2017 Karsten Horsmann <khorsmann@gmail.com> - 1.0.0-3
- ldconfig with /usr/local/lib path in post/un rpm run
* Fri Jan 06 2017 Karsten Horsmann <khorsmann@gmail.com> - 1.0.0-2
- added initscript and logrotate
* Thu Jan 05 2017 Karsten Horsmann <khorsmann@gmail.com> - 1.0.0
- First spec file for CentOS builds, tested on CentOS 6.x
