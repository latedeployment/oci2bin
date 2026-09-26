Name:           oci2bin
Version:        0.19.0
Release:        1%{?dist}
Summary:        Convert OCI/Docker images into mostly self-contained Linux executables

License:        MIT
URL:            https://github.com/latedeployment/oci2bin
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz

ExclusiveArch:  x86_64 aarch64

BuildRequires:  gcc glibc-static texinfo
Requires:       python3
Suggests:       docker
Suggests:       podman
Suggests:       skopeo

%description
oci2bin packages a Docker or OCI image as one mostly self-contained Linux
executable. The artifact runs as a rootless container without Docker, a daemon,
or oci2bin on the target. A normal target needs unprivileged user namespaces
and tar; optional features add feature-specific dependencies.

%prep
%autosetup -n %{name}-%{version}

%build
make loader
make doc

%install
make install DESTDIR=%{buildroot} PREFIX=/usr

%files
/usr/bin/oci2bin
/usr/bin/oci2vm
%ifarch x86_64
/usr/share/oci2bin/build/loader-x86_64
%endif
%ifarch aarch64
/usr/share/oci2bin/build/loader-aarch64
%endif
/usr/share/oci2bin/scripts/*.py
/usr/share/oci2bin/src/loader.c
%{_mandir}/man1/oci2bin.1*
%{_infodir}/oci2bin.info*

%changelog
* Sat Aug 15 2026 latedeployment - 0.19.0-1
- Update to v0.19.0
* Thu Aug 06 2026 latedeployment - 0.18.0-1
- Update to v0.18.0
* Sat Apr 18 2026 latedeployment - 0.9.0-1
- Update to v0.9.0; install all helper scripts
* Tue Mar 10 2026 latedeployment - 0.1.0-1
- Initial package
