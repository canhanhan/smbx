#
# This is loaded when a user activates the plugin. Include scripts here that should be
# loaded automatically at that point.
# 

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
	
	type smb2_fileinfo : record {
		id			: string;
		name		: string;
		tree_name	: string;
		path		: string;
	};
		
	type smb2_session : record {
		files : table[string] of smb2_fileinfo &optional;
	};
	
	global smb2_negotiate_request: event(c: connection, h: smb2_header, security_mode: count , capabilities: count , guid: string , dialects: vector of count);
	global smb2_negotiate_response: event(c: connection, h: smb2_header, security_mode: count , dialect: count , guid: string , capabilities: count , server_time: time , server_boot_time: time );
	global smb2_session_setup_request: event(c: connection, h: smb2_header, flags: count, security_mode: count, capabilities: count, channel: count, previous_session_id: count, buffer: string);
	global smb2_session_setup_response: event(c: connection, h: smb2_header, flags: count, buffer: string);
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
	global smb2_write_request: event(c: connection, h: smb2_header, offset: count);
	global smb2_write_response: event(c: connection, h: smb2_header);
	global smb2_cancel_request: event(c: connection, h: smb2_header);
	global smb2_cancel_response: event(c: connection, h: smb2_header);
	global smb2_query_directory_request: event(c: connection, h: smb2_header);
	global smb2_query_directory_response: event(c: connection, h: smb2_header);
	global smb2_error: event(c: connection, h: smb2_header);
	global smb2_pre_file_transfer: event(c: connection, h: smb2_header, f: smb2_fileinfo);
}

@load ./main.bro 