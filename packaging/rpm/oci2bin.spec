Name:           oci2bin
Version:        0.1.0
Release:        1%{?dist}
Summary:        Convert OCI/Docker images into self-contained ELF executables

License:        MIT
URL:            https://github.com/latedeployment/oci2bin
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

ExclusiveArch:  x86_64

BuildRequires:  musl-gcc musl-libc-static
Requires:       python3 docker

%description
oci2bin converts any Docker (OCI) image into a single executable file
that runs as a rootless container on any Linux machine without Docker,
without a daemon, and without any installation on the target.

%prep
%autosetup -n %{name}-%{version}

%build
make loader

%install
make install PREFIX=%{buildroot}/usr

%files
/usr/bin/oci2bin
/usr/share/oci2bin/build/loader
/usr/share/oci2bin/scripts/build_polyglot.py
/usr/share/oci2bin/src/loader.c

%changelog
* Tue Mar 10 2026 latedeployment - 0.1.0-1
- Initial package
