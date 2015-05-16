# This includes the Netbios Session Service Header and matches on negotiate protocol.
signature dpd_smbx_client {
	ip-proto == tcp
	payload /....\xfeSMB........\x00\x00/
	tcp-state originator
}
signature dpd_smb2_server {
	ip-proto == tcp
	payload /....\xfeSMB........\x00\x00/
	tcp-state responder
	requires-reverse-signature dpd_smbx_client
	enable "SMBx"
}
