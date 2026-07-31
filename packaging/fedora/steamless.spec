Name:           steamless
Version:        b0
Release:        1%{?dist}
Summary:        High-performance, zero-dependency SteamStub DRM unpacker engine

License:        GPL-3.0-only
URL:            https://github.com/staernid/steamless-rs
Source0:        https://github.com/staernid/steamless-rs/archive/refs/tags/%{version}.tar.gz#/%{name}-%{version}.tar.gz

BuildRequires:  cargo-rpm-macros >= 25
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
install -D -m 0755 target/release/libsteamless_c.so %{buildroot}%{_libdir}/libsteamless_c.so

%check
cargo test --workspace

%files
%license LICENSE
%doc README.md
%{_bindir}/steamless
%{_libdir}/libsteamless_c.so

%changelog
* Fri Jul 31 2026 Staernid <vitezfh@gmail.com> - b0-1
- Release build




