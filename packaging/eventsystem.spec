Name:       eventsystem
Summary:    Event system library
Version:    0.0.1
Release:    1
Group:      System/Libraries
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  pkgconfig(ecore)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(capi-base-common)

Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description
Event System Library

%package devel
Summary:    Event system library (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Event system library (devel)

%prep
%setup -q

%build
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"


%cmake .
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest eventsystem.manifest
%defattr(-,root,root,-)
%{_libdir}/libeventsystem.so.*
/usr/share/license/%{name}

%files devel
%defattr(-,root,root,-)
%{_includedir}/*.h
%{_libdir}/libeventsystem.so
%{_libdir}/pkgconfig/eventsystem.pc
