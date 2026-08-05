Name:           sow-yum-relative-neutral
Version:        1.0
Release:        1
Summary:        Noarch RPM for the SOW relative YUM pool proof
License:        MIT
BuildArch:      noarch

%description
Minimal noarch package used by both SOW managed YUM architecture views.

%install
mkdir -p %{buildroot}/usr/share/sow-yum-relative
printf 'neutral noarch payload\n' > %{buildroot}/usr/share/sow-yum-relative/neutral.txt
chmod 0644 %{buildroot}/usr/share/sow-yum-relative/neutral.txt

%files
/usr/share/sow-yum-relative/neutral.txt
