Name:           sie-nmsg
Version:        1.3.0
Release:        1%{?dist}
Summary:	SIE message module for libnmsg

License:        Apache-2.0
URL:            https://github.com/farsightsec/sie-nmsg
Source0:        https://dl.farsightsecurity.com/dist/sie-nmsg/sie-nmsg-%{version}.tar.gz

BuildRequires:  libpcap-devel protobuf-c-devel wdns-devel libnmsg-devel

%description

%package -n nmsg-msg-module-sie
Summary:	SIE message module plugin for libnmsg
Requires:	libpcap protobuf-c

%description -n nmsg-msg-module-sie
This package extends the libnmsg runtime to support the following
message types: sie/reputation, sie/dnsdedupe, sie/qr, sie/newdomain,
sie/dnsnx, and sie/delay.pb.

%package -n nmsg-msg-module-sie-devel
Summary:        SIE message module plugin for libnmsg (development files)
Requires:       nmsg-msg-module-sie%{?_isa} = %{version}-%{release}

%description -n nmsg-msg-module-sie-devel
This package contains the static library and header files for SIE NMSG.

%prep
%setup -q -n sie-nmsg-%{version}


%build
[ -x configure ] || autoreconf -fvi
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install


%files -n nmsg-msg-module-sie
%defattr(-,root,root,-)
%{_libdir}/nmsg/*.so

%files -n nmsg-msg-module-sie-devel
%{_libdir}/nmsg/*.a
%{_libdir}/nmsg/*.la
%{_includedir}/*


%doc

%changelog

