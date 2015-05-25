@load base/frameworks/files
@load-sigs ./dpd

module SMBx;

global smbports = { 139/tcp, 445/tcp };
redef capture_filters = { ["smb"] = "port 445" };

redef record connection += {
	smbx: smb2_session &optional;	
};

redef record Files::Info += {
	path: string &optional &log;	
};

event bro_init() &priority=5
{
    Analyzer::register_for_ports(Analyzer::ANALYZER_SMBX, smbports);
}

event smb2_pre_file_transfer(c: connection, h: smb2_header, f: smb2_fileinfo)
{
	if (!c?$smbx)
	{
		local t : table[string] of smb2_fileinfo &read_expire=5mins;
		local s: smb2_session = smb2_session();
		s$files = t;
		c$smbx = s;
	}
	
	c$smbx$files[f$id] = f;
}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
{
	if (!c?$smbx || f$source != "SMBX") 
		return;
		
	if (f$id !in c$smbx$files) 
		return;

	local f2 = c$smbx$files[f$id];
	f$info$filename = f2$name;
	f$info$path = f2$path;
}
