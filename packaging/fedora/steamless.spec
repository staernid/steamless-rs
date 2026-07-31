Name:           steamless
Version:        1.0.0
Release:        1%{?dist}
Summary:        High-performance, zero-dependency SteamStub DRM unpacker engine

License:        GPL-3.0-only
URL:            https://github.com/staernid/steamless-rs
Source0:        steamless-rs.tar.gz

BuildRequires:  cargo
BuildRequires:  rust >= 1.70.0
BuildRequires:  gcc

%description
Steamless is a DRM unpacker for SteamStub variants applied to executables released on Steam.
This is the portable Rust engine supplying a fast CLI utility and C ABI shared library.

%prep
%autosetup -c

%build
cargo build --release --workspace

%install
rm -rf %{buildroot}
install -D -m 0755 target/release/steamless %{buildroot}%{_bindir}/steamless
install -D -m 0755 target/release/libsteamless.so %{buildroot}%{_libdir}/libsteamless.so

%files
%license LICENSE
%doc README.md
%{_bindir}/steamless
%{_libdir}/libsteamless.so

%changelog
* Fri Jul 31 2026 Staernid <vitezfh@gmail.com> - 1.0.0-1
- Initial Fedora COPR RPM package for steamless-rs
