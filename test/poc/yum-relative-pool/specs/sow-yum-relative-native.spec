Name:           sow-yum-relative-native
Version:        1.0
Release:        1
Summary:        Native RPM for the SOW relative YUM pool proof
License:        MIT
BuildArch:      x86_64

%description
Minimal x86_64 package used only by the SOW managed YUM layout proof.

%install
mkdir -p %{buildroot}/usr/share/sow-yum-relative
printf 'native x86_64 payload\n' > %{buildroot}/usr/share/sow-yum-relative/native.txt
chmod 0644 %{buildroot}/usr/share/sow-yum-relative/native.txt

%files
/usr/share/sow-yum-relative/native.txt
