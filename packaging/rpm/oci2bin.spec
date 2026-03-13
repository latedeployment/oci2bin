Name:           oci2bin
Version:        0.1.0
Release:        1%{?dist}
Summary:        Convert OCI/Docker images into self-contained ELF executables

License:        MIT
URL:            https://github.com/latedeployment/oci2bin
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

ExclusiveArch:  x86_64 aarch64

BuildRequires:  gcc glibc-static texinfo
Requires:       python3 docker

%description
oci2bin converts any Docker (OCI) image into a single executable file
that runs as a rootless container on any Linux machine without Docker,
without a daemon, and without any installation on the target.

%prep
%autosetup -n %{name}-%{version}

%build
make loader
make doc

%install
make install PREFIX=%{buildroot}/usr

%files
/usr/bin/oci2bin
%ifarch x86_64
/usr/share/oci2bin/build/loader-x86_64
%endif
%ifarch aarch64
/usr/share/oci2bin/build/loader-aarch64
%endif
/usr/share/oci2bin/scripts/build_polyglot.py
/usr/share/oci2bin/src/loader.c
%{_mandir}/man1/oci2bin.1*
%{_infodir}/oci2bin.info*

%changelog
* Tue Mar 10 2026 latedeployment - 0.1.0-1
- Initial package
