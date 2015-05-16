#
# This is loaded when a user activates the plugin. Include scripts here that should be
# loaded automatically at that point.
# 

global smbports = { 139/tcp, 445/tcp };
redef capture_filters = { ["smb"] = "port 445" };

export {
	type smb2_header : record {
		header_size   : count;
		status        : count;
		command       : count;
		flags         : count;
		message_id    : count;
		tree_id       : count;
		session_id    : count;
		structure_size: count;
	};
	
	global smb2_negotiate_request: event(c: connection, h: smb2_header, security_mode: count , capabilities: count , guid: string , dialects: vector of count);
	global smb2_negotiate_response: event(c: connection, h: smb2_header, security_mode: count , dialect: count , guid: string , capabilities: count , server_time: time , server_boot_time: time );
	global smb2_session_setup_request: event(c: connection, h: smb2_header, flags: count, security_mode: count, capabilities: count, channel: count, previous_session_id: count, buffer_len: count);
	global smb2_session_setup_response: event(c: connection, h: smb2_header, flags: count, buffer_len: count);
	global smb2_logoff_request: event(c: connection, h: smb2_header);
	global smb2_logoff_response: event(c: connection, h: smb2_header);	
	global smb2_treeconnect_request: event(c: connection, h: smb2_header, path: string);
	global smb2_treeconnect_response: event(c: connection, h: smb2_header, flags: count, capabilities: count, maximal_access: count);
	global smb2_tree_disconnect_request: event(c: connection, h: smb2_header);
	global smb2_tree_disconnect_response: event(c: connection, h: smb2_header);
	global smb2_create_request: event(c: connection, h: smb2_header, access_mask: count, file_attrs: count, share_access: count, disposition: count, create_options: count, path: string);
	global smb2_create_response: event(c: connection, h: smb2_header, create_action: count, creation_time: time, last_access_time: time, last_write_time: time, change_time: time, alloc_size: count, eof: count, file_attrs: count);
	global smb2_close_request: event(c: connection, h: smb2_header, flags: count);
	global smb2_close_response: event(c: connection, h: smb2_header, flags: count, creation_time: time, last_access_time: time, last_write_time: time, change_time: time, alloc_size: count, eof: count, file_attrs: count);
	global smb2_read_request: event(c: connection, h: smb2_header, flags: count, length: count, offset: count, minimum_count: count, channel: count, remaining_bytes: count);
	global smb2_read_response: event(c: connection, h: smb2_header, length: count, remaining: count);
	global smb2_write_request: event(c: connection, h: smb2_header);
	global smb2_write_response: event(c: connection, h: smb2_header);
	global smb2_cancel_request: event(c: connection, h: smb2_header);
	global smb2_cancel_response: event(c: connection, h: smb2_header);
	global smb2_query_directory_request: event(c: connection, h: smb2_header);
	global smb2_query_directory_response: event(c: connection, h: smb2_header);
	global smb2_error: event(c: connection, h: smb2_header);
		
	type smb_tree : record {
		name : string;
		fid_table: table[count] of string;	
		write_table: table[count] of count;
		read_table: table[count] of count;
		last_filename : string;
	};

	type smb_session : record {
		tid_table: table[count] of smb_tree;
		last_treepath : string;
	};
}


redef record connection += {
	smb_session: smb_session &optional;
};


event smb2_error(c: connection, h: smb2_header) 
{
	print fmt("Error (mid: %d): 0x%8x", h$message_id, h$status);
}

event smb2_negotiate_request(c: connection, h: smb2_header, security_mode: count, capabilities: count, guid: string, dialects: vector of count)
{	
	print fmt("Negotiate request (mid: %d): %s", h$message_id, guid);
}

event smb2_negotiate_response(c: connection, h: smb2_header, security_mode: count, dialect: count, guid: string, capabilities: count, server_time: time, server_boot_time: time)
{	
	print fmt("Negotiate response (mid: %d): %d; dialect: %d, server_time: %s; boot: %s, guid: %s", h$message_id, capabilities, dialect, strftime("%Y-%m-%d %H:%M:%S", server_time), strftime("%Y-%m-%d %H:%M:%S", server_boot_time), guid);
}

event smb2_session_setup_response(c: connection, h: smb2_header, flags: count, buffer_len: count)
{
#	local session: smb_session;
#	c$smb_session = session;
	print fmt("Session setup response (mid: %d): flags: %d, buffer: %d", h$message_id, flags, buffer_len);	
}

event smb2_session_setup_request(c: connection, h: smb2_header, flags: count, security_mode: count, capabilities: count, channel: count, previous_session_id: count, buffer_len: count)
{
#	local session: smb_session;
#	c$smb_session = session;
	print fmt("Session setup request (mid: %d): flags: %d, security_mode: %d, capabilities: %d, previous_sid: %d, buffer: %d", h$message_id, flags, security_mode, capabilities, previous_session_id, buffer_len);
}

event smb2_logoff_request(c: connection, h: smb2_header)
{
	print fmt("Logoff request (mid: %d)", h$message_id);
}

event smb2_logoff_response(c: connection, h: smb2_header)
{
	print fmt("Logoff response (mid: %d)", h$message_id);
	#if (!c?$smb_session)
	#	return;
		
	#clear_table(c$smb_session$tid_table);
	#delete c$smb_session;	
}

event smb2_treeconnect_request(c: connection, h: smb2_header, path: string)
{
	print fmt("Tree connect request (mid: %d): %s", h$message_id, path);
	#if (!c?$smb_session)
	#	return;
		
	#c$smb_session$last_treepath = path;
}

event smb2_treeconnect_response(c: connection, h: smb2_header, flags: count, capabilities: count, maximal_access: count)
{
	print fmt("Tree connect response (mid: %d): flags: %d, capabilities: %d, maximal_access: %d", h$message_id, flags, capabilities, maximal_access);
	#if (!c?$smb_session || !c$smb_session?$last_treepath)
	#	return;
		
	#local tree : smb_tree;
	#tree$name = c$smb_session$last_treepath;
	#c$smb_session$tid_table[tid] = tree;	
}

event bro_init() &priority=5
{
		print "test"; 
        Analyzer::register_for_ports(Analyzer::ANALYZER_SMBX, smbports);
}


event smb2_tree_disconnect_request(c: connection, h: smb2_header)
{
	# if (!c?$smb_session || tid !in c$smb_session$tid_table)
		# return;
				
	# clear_table(c$smb_session$tid_table[tid]$fid_table);
	# clear_table(c$smb_session$tid_table[tid]$write_table);
	# clear_table(c$smb_session$tid_table[tid]$read_table);
	# delete c$smb_session$tid_table[tid];
	
	print fmt("Tree disconnect request (mid: %d)", h$message_id);
}

event smb2_tree_disconnect_response(c: connection, h: smb2_header)
{
	print fmt("Tree disconnect response (mid: %d)", h$message_id);
}

event smb2_create_request(c: connection, h: smb2_header, access_mask: count, file_attrs: count, share_access: count, disposition: count, create_options: count, path: string)
{
	# if (!c?$smb_session || tid !in c$smb_session$tid_table)
		# return;
		
	# c$smb_session$tid_table[tid]$last_filename = path;
	print fmt("Create request (mid: %d): am: %d, fa: %d, sa: %d, dis: %d, co: %d, file: %s", h$message_id, access_mask, file_attrs, share_access, disposition, create_options, path);
}

event smb2_create_response(c: connection, h: smb2_header, create_action: count, creation_time: time, last_access_time: time, last_write_time: time, change_time: time, alloc_size: count, eof: count, file_attrs: count)
{
	# if (!c?$smb_session|| tid !in c$smb_session$tid_table || !c$smb_session$tid_table[tid]?$last_filename)
		# return;
		
	# c$smb_session$tid_table[tid]$fid_table[fid] = c$smb_session$tid_table[tid]$last_filename;
	local creation_time_s: string = strftime("%Y-%m-%d %H:%M:%S", creation_time);
	local last_access_time_s: string = strftime("%Y-%m-%d %H:%M:%S", last_access_time);
	local last_write_time_s: string = strftime("%Y-%m-%d %H:%M:%S", last_write_time);
	local change_time_s: string = strftime("%Y-%m-%d %H:%M:%S", change_time);
	print fmt("Create response (mid: %d): ca: %d, ct: %s, at: %s, wr: %s, ct: %s, as: %d, eof: %d, fa: %d", h$message_id, create_action, creation_time_s, last_access_time_s, last_write_time_s, change_time_s, alloc_size, eof, file_attrs);
}

event smb2_close_request(c: connection, h: smb2_header, flags: count)
{
	print fmt("Close request (mid: %d): %d", h$message_id, flags);
}

event smb2_close_response(c: connection, h: smb2_header, flags: count, creation_time: time, last_access_time: time, last_write_time: time, change_time: time, alloc_size: count, eof: count, file_attrs: count)
{
	local creation_time_s: string = strftime("%Y-%m-%d %H:%M:%S", creation_time);
	local last_access_time_s: string = strftime("%Y-%m-%d %H:%M:%S", last_access_time);
	local last_write_time_s: string = strftime("%Y-%m-%d %H:%M:%S", last_write_time);
	local change_time_s: string = strftime("%Y-%m-%d %H:%M:%S", change_time);
	print fmt("Close response (mid: %d): flags: %d, ct: %s, at: %s, wr: %s, ct: %s, as: %d, eof: %d, fa: %d", h$message_id, flags, creation_time_s, last_access_time_s, last_write_time_s, change_time_s, alloc_size, eof, file_attrs);
}
	
event smb2_read_request(c: connection, h: smb2_header, flags: count, length: count, offset: count, minimum_count: count, channel: count, remaining_bytes: count)
{
	print fmt("Read request (mid: %d): flags: %d, l: %d, o: %d, mc: %d, c: %d, rb: %d", h$message_id, flags, length, offset, minimum_count, channel, remaining_bytes);
}

event smb2_read_response(c: connection, h: smb2_header, length: count, remaining: count)
{
	print fmt("Read response (mid: %d): l: %d, r: %d", h$message_id, length, remaining);
}

event smb2_write_request(c: connection, h: smb2_header) 
{
	print fmt("Write request (mid: %d)", h$message_id);
}

event smb2_write_response(c: connection, h: smb2_header) 
{
	print fmt("Write response (mid: %d)", h$message_id);
}

# event smb2_close_request(c: connection, h: smb2_header, session_id: count, tid: count, fid: count, flags: count)
# {
	# if (!c?$smb_session || tid !in c$smb_session$tid_table  || fid !in c$smb_session$tid_table[tid]$fid_table)
		# return;
				
	# delete c$smb_session$tid_table[tid]$fid_table[fid];
# }

# event smb2_write_request(c: connection, h: smb2_header, session_id: count, tid: count, fid: count, data_len: count, offset: count, data_remaining: count, flags: count)
# {
	# if (!c?$smb_session || tid !in c$smb_session$tid_table || fid !in c$smb_session$tid_table[tid]$fid_table)
		# return;

	# print fmt("Write to: %s\\%s", c$smb_session$tid_table[tid]$name, c$smb_session$tid_table[tid]$fid_table[fid]);
# }