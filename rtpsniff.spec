Name:           rtpsniff
Version:        1.0.0
Release:        1%{?dist}
Summary:        rtpsniff
Group:          Networking/Utilities
License:        GPLv3
URL:            https://github.com/lmangani/rtpsniff
Source0:        https://github.com/lmangani/rtpsniff/archive/master.zip
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires:  make, unzip, libtool, gcc

%description
RTPSniff is a tool to sniff RTP traffic and show stats about it.

%prep
%setup -q -n %{name}-master

%build
make MOD_OUT=out_json

%install
rm -rf %{buildroot}
make install PREFIX=%{buildroot}/usr/local

%clean
rm -rf %{buildroot}

%files
/usr/local/lib/libslowpoll.so
/usr/local/sbin/rtpsniff
%defattr(-,root,root,-)
%doc

%changelog
* Thu Jan 05 2017 Karsten Horsmann <khorsmann@gmail.com> - 1.0.0
- First spec file for CentOS builds, tested on CentOS 6.x
