#define TIMESTAMP(d) (double)(d > 0 ? (d / 10000000) - 11644473600 : 0)

#include <sstream>
#include <string>
#include "Event.h"
#include "Message.h"
#include "binpac_bytestring.h"
#include "file_analysis/Manager.h"

template<typename T>
std::string toString(const T& value)
{
    std::ostringstream oss;
    oss << value;
    return oss.str();
}

namespace SMBx
{	
	const static EventHandlerPtr smb2_negotiate_request = internal_handler("smb2_negotiate_request"); 
	const static EventHandlerPtr smb2_negotiate_response = internal_handler("smb2_negotiate_response"); 
	const static EventHandlerPtr smb2_session_setup_request = internal_handler("smb2_session_setup_request"); 
	const static EventHandlerPtr smb2_session_setup_response = internal_handler("smb2_session_setup_response"); 
	const static EventHandlerPtr smb2_logoff_request = internal_handler("smb2_logoff_request"); 
	const static EventHandlerPtr smb2_logoff_response = internal_handler("smb2_logoff_response");
	const static EventHandlerPtr smb2_treeconnect_request = internal_handler("smb2_treeconnect_request"); 
	const static EventHandlerPtr smb2_treeconnect_response = internal_handler("smb2_treeconnect_response"); 
	const static EventHandlerPtr smb2_tree_disconnect_request = internal_handler("smb2_tree_disconnect_request");
	const static EventHandlerPtr smb2_tree_disconnect_response = internal_handler("smb2_tree_disconnect_response");
	const static EventHandlerPtr smb2_create_request = internal_handler("smb2_create_request");
	const static EventHandlerPtr smb2_create_response = internal_handler("smb2_create_response");
	const static EventHandlerPtr smb2_close_request = internal_handler("smb2_close_request");
	const static EventHandlerPtr smb2_close_response = internal_handler("smb2_close_response");
	const static EventHandlerPtr smb2_read_request = internal_handler("smb2_read_request");
	const static EventHandlerPtr smb2_read_response = internal_handler("smb2_read_response");
	const static EventHandlerPtr smb2_write_request = internal_handler("smb2_write_request");
	const static EventHandlerPtr smb2_write_response = internal_handler("smb2_write_response");
	const static EventHandlerPtr smb2_cancel_request = internal_handler("smb2_cancel_request");
	const static EventHandlerPtr smb2_cancel_response = internal_handler("smb2_cancel_response");
	const static EventHandlerPtr smb2_query_directory_request = internal_handler("smb2_query_directory_request");
	const static EventHandlerPtr smb2_query_directory_response = internal_handler("smb2_query_directory_response");
	const static EventHandlerPtr smb2_error = internal_handler("smb2_error");
	static RecordType* smb2_header = NULL;
		
	SMB2_Message::SMB2_Message(Analyzer* a, Reader* r)
	{
		analyzer = a;
		reader = r;
	}
		
	bool SMB2_Header::New() 
	{
		header_size = *reader->read<uint16>();
		reader->skip(2);
		status =  *reader->read<uint32>();
		command = *reader->read<uint16>();
		reader->skip(2);
		flags = *reader->read<uint32>();
		next_command = *reader->read<uint32>();
		messageId = *reader->read<uint64>();
		reader->skip(4);
		treeId = *reader->read<uint32>();
		sessionId = *reader->read<uint64>();
		reader->skip(16);
		structure_size = *reader->read<uint16>() - 1;
		is_response = flags & 0x00000001;
		
		return true;
	}
	
	val_list* SMB2_Body::create_value_list() 
	{
		if (smb2_header == NULL)
			 smb2_header = internal_type("smb2_header")->AsRecordType();
		 
		RecordVal* rv = new RecordVal(smb2_header);
		rv->Assign(0, new Val(header->header_size, TYPE_COUNT));
		rv->Assign(1, new Val(header->status, TYPE_COUNT));
		rv->Assign(2, new Val(header->command, TYPE_COUNT));
		rv->Assign(3, new Val(header->flags, TYPE_COUNT));
		rv->Assign(4, new Val(header->messageId, TYPE_COUNT));
		rv->Assign(5, new Val(header->treeId, TYPE_COUNT));
		rv->Assign(6, new Val(header->sessionId, TYPE_COUNT));
		rv->Assign(7, new Val(header->structure_size, TYPE_COUNT));
		
		val_list* vl = new val_list;
		vl->append(analyzer->Conn()->BuildConnVal());	
		vl->append(rv);   
		
		return vl;		
	}	
	
	bool SMB2_Chunked_Body::GetData() 
	{
		if (data_len > 0) 
		{
			reader->skip(data_offset - reader->current_pos + header->beginning);
			uint32 remaining = reader->len - reader->current_pos;
			data_received = remaining;
			
			//printf("mid: %lld, r: %d, o: %d, dl: %d, l: %d, r: %d\n", header->messageId, data_received, data_offset, data_len, 0, data_received == data_len);
			if (data_len > remaining) 
			{				
				ChunkReceived(remaining);
				return false;
			} else {			
				ChunkReceived(data_len);						
				return true;
			}
		}	

		return true;
	}
	
	bool SMB2_Chunked_Body::Continue()
	{			
		uint32 remaining = std::min(data_len - data_received, (uint32)reader->len);				
		data_received += remaining;
		
		//printf("dr: %d, dl: %d, r: %d, rl: %d, r: %d\n", data_received, data_len, remaining, reader->len,data_received == data_len);	
		ChunkReceived(remaining);
			
		if (data_received < data_len) 
			return false;
				
		if (data_received > data_len) 
			ChunkFailed();
		
		TriggerEvent();

		return true;	
	}		
	
	void SMB2_FileMessage::TriggerEvent() 
	{
		printf("File closed\n\n");
		file_mgr->EndOfFile(file_id);		
	}
	
	bool SMB2_FileMessage::New()
	{
		file_id = file_mgr->HashHandle(toString(header->messageId));
		file_id = file_mgr->SetSize(data_len, analyzer->GetAnalyzerTag(), analyzer->Conn(), !header->is_response, file_id);
		printf("asdada %s, %d\n\n\n\n", file_id.c_str(), data_len);

		if (!GetData())
			return false;
				
		TriggerEvent();
		
		return true;		
	}
	
	void SMB2_FileMessage::ChunkReceived(uint32 length)
	{		
		binpac::bytestring data((uint8*)reader->read<uint8>(length), (int)length);
		printf("File write write %s - %d - %d - %d\n\n", file_id.c_str(), length, data_len, data_received);
		file_id = file_mgr->DataIn(data.data(), length, analyzer->GetAnalyzerTag(), analyzer->Conn(), !header->is_response, file_id);
	}
	

	void SMB2_FileMessage::ChunkFailed() 
	{
		printf("Missed a file... (File length: %d, Collected: %d)\n", data_len, data_received);
		file_mgr->IgnoreFile(file_id);
	}	

	bool SMB2_Error::New() 
	{
		reader->skip(2);
		byte_count = *reader->read<uint32>();
		reader->skip(byte_count || 1);
		
		if (smb2_error) {
			val_list* vl = create_value_list();
			mgr.QueueEvent(smb2_error, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());
		}
		
		return true;
	}
	
	bool SMB2_Negotiate_Request::New() 
	{
		dialect_count = *reader->read<uint16>();
		security_mode = *reader->read<uint16>();
		reader->skip(2);
		capabilities = *reader->read<uint32>();
		client_guid = reader->read_uuid();
		reader->skip(8);

		dialects = reader->read<uint16>(dialect_count);	
		dialectsVal = new VectorVal(vector_of_count);
		for(uint i=0; i < dialect_count; i++)
			dialectsVal->Assign(i, new Val(dialects[i], TYPE_COUNT));

		if (smb2_negotiate_request) {
			val_list* vl = create_value_list();		
			vl->append(new Val(security_mode, TYPE_COUNT));
			vl->append(new Val(capabilities, TYPE_COUNT));
			vl->append(new StringVal(client_guid));
			vl->append(dialectsVal);		
			
			mgr.QueueEvent(smb2_negotiate_request, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}

		return true;		
	}
	
	bool SMB2_Negotiate_Response::New()
	{		
		security_mode = *reader->read<uint16>();
		dialect = *reader->read<uint16>(); 
		reader->skip(2);
		server_guid = reader->read_uuid();
		capabilities = *reader->read<uint32>();
		reader->skip(12);
		server_time = *reader->read<uint64>();
		server_boot_time = *reader->read<uint64>();
		buffer_offset = *reader->read<uint16>();
		buffer_len = *reader->read<uint16>();
		reader->skip(4);
		
		if (buffer_len > 0) 
		{
			reader->skip(header->beginning + buffer_offset - reader->current_pos);
			reader->skip(buffer_len);
		}
		
		if (smb2_negotiate_response) {	
			val_list* vl = create_value_list();				
			vl->append(new Val(security_mode, TYPE_COUNT));
			vl->append(new Val(dialect, TYPE_COUNT));
			vl->append(new StringVal(server_guid));
			vl->append(new Val(capabilities, TYPE_COUNT));
			vl->append(new Val(TIMESTAMP(server_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(server_boot_time), TYPE_TIME));

			mgr.QueueEvent(smb2_negotiate_response, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}
		
		return true;
	}	
	
	bool SMB2_Session_Setup_Request::New()
	{		
		flags = *reader->read<uint8>();
		security_mode = *reader->read<uint8>();
		capabilities = *reader->read<uint32>();
		channel = *reader->read<uint32>();
		buffer_offset = *reader->read<uint16>();
		buffer_len = *reader->read<uint16>();
		previous_session_id = *reader->read<uint64>();
			
		if (buffer_len > 0) 
		{
			reader->skip(buffer_offset - reader->current_pos + header->beginning);
			reader->skip(buffer_len);
		}

		if (smb2_session_setup_request) {	
			val_list* vl = create_value_list();
			vl->append(new Val(flags, TYPE_COUNT));
			vl->append(new Val(security_mode, TYPE_COUNT));
			vl->append(new Val(capabilities, TYPE_COUNT));
			vl->append(new Val(channel, TYPE_COUNT));
			vl->append(new Val(previous_session_id, TYPE_COUNT));
			vl->append(new Val(buffer_len, TYPE_COUNT));

			mgr.QueueEvent(smb2_session_setup_request, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}
	
		return true;
	}	
	
	bool SMB2_Session_Setup_Response::New()
	{		
		flags = *reader->read<uint16>();
		buffer_offset = *reader->read<uint16>();
		buffer_len = *reader->read<uint16>();
		
		if (buffer_len > 0) 
		{
			reader->skip(buffer_offset - reader->current_pos + header->beginning);
			reader->skip(buffer_len);
		}

		if (smb2_session_setup_response) {	
			val_list* vl = create_value_list();
			vl->append(new Val(flags, TYPE_COUNT));
			vl->append(new Val(buffer_len, TYPE_COUNT));

			mgr.QueueEvent(smb2_session_setup_response, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}	
	
	bool SMB2_Logoff_Request::New()
	{		
		reader->skip(2);
		
		if (smb2_logoff_request) {	
			val_list* vl = create_value_list();

			mgr.QueueEvent(smb2_logoff_request, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}	

	bool SMB2_Logoff_Response::New()
	{		
		reader->skip(2);
		
		if (smb2_logoff_response) {	
			val_list* vl = create_value_list();

			mgr.QueueEvent(smb2_logoff_response, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}		

	bool SMB2_Tree_Connect_Request::New()
	{		
		reader->skip(2);
		path_offset = *reader->read<uint16>();
		path_length = *reader->read<uint16>();
		
		if (path_length > 0)
			reader->skip(path_offset - reader->current_pos + header->beginning);	
		
		if (smb2_treeconnect_request) {	
			uint16 path_size = path_length / 2; // path_length is byte length for UTF-16LE
			val_list* vl = create_value_list();
			vl->append(new StringVal(reader->read_string(path_size)));
			
			mgr.QueueEvent(smb2_treeconnect_request, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}		

	bool SMB2_Tree_Connect_Response::New()
	{		
		share_type = *reader->read<uint8>();
		reader->skip(1);
		share_flags = *reader->read<uint32>();
		capabilities = *reader->read<uint32>();
		maximal_access = *reader->read<uint32>();
	
		if (smb2_treeconnect_response) {	
			val_list* vl = create_value_list();
			vl->append(new Val(share_flags, TYPE_COUNT));
			vl->append(new Val(capabilities, TYPE_COUNT));
			vl->append(new Val(maximal_access, TYPE_COUNT));
						
			mgr.QueueEvent(smb2_treeconnect_response, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}		

	bool SMB2_Tree_Disconnect_Request::New()
	{		
		reader->skip(2);
	
		if (smb2_tree_disconnect_request) {	
			val_list* vl = create_value_list();

			mgr.QueueEvent(smb2_tree_disconnect_request, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;	
	}			
	
	bool SMB2_Tree_Disconnect_Response::New()
	{		
		reader->skip(2);
		
		if (smb2_tree_disconnect_response) {	
			val_list* vl = create_value_list();

			mgr.QueueEvent(smb2_tree_disconnect_response, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}		

	bool SMB2_Create_Request::New()
	{		
		reader->skip(1);
		oplock = *reader->read<uint8>();
		impersonation_level = *reader->read<uint32>();
		flags = *reader->read<uint64>();
		reader->skip(8);
		access_mask = *reader->read<uint32>();
		file_attrs = *reader->read<uint32>();
		share_access = *reader->read<uint32>();
		disposition = *reader->read<uint32>();
		create_options = *reader->read<uint32>();
		filename_offset = *reader->read<uint16>();
		filename_len = *reader->read<uint16>();
		context_offset = *reader->read<uint32>();
		context_len = *reader->read<uint32>();
		
		BroString* filename = NULL;
		if (filename_len > 0) {
			reader->skip(filename_offset - reader->current_pos + header->beginning);
			filename = reader->read_string(filename_len/2);
		}
		
		if (context_len > 0) {
			reader->skip(context_offset - reader->current_pos + header->beginning);
			reader->skip(context_len);
		}		
		
		if (smb2_create_request) {	
			val_list* vl = create_value_list();
			vl->append(new Val(access_mask, TYPE_COUNT));
			vl->append(new Val(file_attrs, TYPE_COUNT));
			vl->append(new Val(share_access, TYPE_COUNT));
			vl->append(new Val(disposition, TYPE_COUNT));
			vl->append(new Val(create_options, TYPE_COUNT));
			vl->append(new StringVal(filename != NULL ? filename : new BroString()));

			mgr.QueueEvent(smb2_create_request, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}			
	
	bool SMB2_Create_Response::New()
	{		
		oplock = *reader->read<uint8>();
		reader->skip(1);
		create_action = *reader->read<uint32>();
		creation_time = *reader->read<uint64>();
		last_access_time = *reader->read<uint64>();
		last_write_time = *reader->read<uint64>();
		change_time = *reader->read<uint64>();
		alloc_size = *reader->read<uint64>();
		eof = *reader->read<uint64>();
		file_attrs = *reader->read<uint32>();
		reader->skip(4);
		persistent_file_id = *reader->read<uint64>();
		volatile_file_id = *reader->read<uint64>();
		context_offset = *reader->read<uint32>();
		context_len = *reader->read<uint32>();	

		if (context_len > 0) {
			reader->skip(context_offset - reader->current_pos + header->beginning);
			reader->skip(context_len);
		}
	
		if (smb2_create_response) {	
			val_list* vl = create_value_list();
			vl->append(new Val(create_action, TYPE_COUNT));
			vl->append(new Val(TIMESTAMP(creation_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(last_access_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(last_write_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(change_time), TYPE_TIME));
			vl->append(new Val(alloc_size, TYPE_COUNT));
			vl->append(new Val(eof, TYPE_COUNT));
			vl->append(new Val(file_attrs, TYPE_COUNT));
			
			mgr.QueueEvent(smb2_create_response, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}	

	bool SMB2_Close_Request::New()
	{		
		flags = *reader->read<uint16>();
		reader->skip(4);
		uint64 persistent_file_id = *reader->read<uint64>();
		volatile_file_id = *reader->read<uint64>();	
		
		if (smb2_close_request) {	
			val_list* vl = create_value_list();
			vl->append(new Val(flags, TYPE_COUNT));
						
			mgr.QueueEvent(smb2_close_request, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}	
	
	bool SMB2_Close_Response::New()
	{		
		flags = *reader->read<uint16>();
		reader->skip(4);
		creation_time = *reader->read<uint64>();
		last_access_time = *reader->read<uint64>();
		last_write_time = *reader->read<uint64>();
		change_time = *reader->read<uint64>();
		alloc_size = *reader->read<uint64>();
		eof = *reader->read<uint64>();
		file_attrs = *reader->read<uint32>();		
		
		if (smb2_close_response) {	
			val_list* vl = create_value_list();
			vl->append(new Val(flags, TYPE_COUNT));
			vl->append(new Val(TIMESTAMP(creation_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(last_access_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(last_write_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(change_time), TYPE_TIME));
			vl->append(new Val(alloc_size, TYPE_COUNT));
			vl->append(new Val(eof, TYPE_COUNT));
			vl->append(new Val(file_attrs, TYPE_COUNT));
			
			mgr.QueueEvent(smb2_close_response, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
		
		return true;
	}	
	
	bool SMB2_Read_Request::New()
	{		
		reader->skip(1);
		flags = *reader->read<uint8>();
		length = *reader->read<uint32>();
		offset = *reader->read<uint64>();
		persistent_file_id = *reader->read<uint64>();
		volatile_file_id = *reader->read<uint64>();
		minimum_count = *reader->read<uint32>();
		channel = *reader->read<uint32>();
		remaining_bytes = *reader->read<uint32>();
		channel_info_offset = *reader->read<uint16>();
		channel_info_len = *reader->read<uint16>();
		
		if (channel_info_len > 0) 
		{
			reader->skip(channel_info_offset - reader->current_pos + header->beginning);
			reader->skip(channel_info_len);
		} else {
			reader->skip(1);
		}
						
		if (smb2_read_request) {	
			val_list* vl = create_value_list();
			vl->append(new Val(flags, TYPE_COUNT));
			vl->append(new Val(length, TYPE_COUNT));
			vl->append(new Val(offset, TYPE_COUNT));
			vl->append(new Val(minimum_count, TYPE_COUNT));
			vl->append(new Val(channel, TYPE_COUNT));
			vl->append(new Val(remaining_bytes, TYPE_COUNT));			

			mgr.QueueEvent(smb2_read_request, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}	
		
	bool SMB2_Read_Response::New()
	{		
		data_offset = *reader->read<uint8>();
		reader->skip(1);
		data_len = *reader->read<uint32>();
		data_remaining = *reader->read<uint32>();
		reader->skip(4);
		
		return SMB2_FileMessage::New();		
	}	
	
	void SMB2_Read_Response::TriggerEvent()
	{		
		SMB2_FileMessage::TriggerEvent();
		
		if (smb2_read_response) {	
			val_list* vl = create_value_list();
			vl->append(new Val(data_len, TYPE_COUNT));
			vl->append(new Val(data_remaining, TYPE_COUNT));			

			mgr.QueueEvent(smb2_read_response, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	}	
		  	 
	bool SMB2_Write_Request::New()
	{				
		data_offset = *reader->read<uint16>();
		data_len = *reader->read<uint32>();
		offset = *reader->read<uint64>();
		persistent_file_id = *reader->read<uint64>();
		volatile_file_id = *reader->read<uint64>();
		channel = *reader->read<uint32>();
		data_remaining = *reader->read<uint32>();
		channel_info_offset = *reader->read<uint16>();
		channel_info_len = *reader->read<uint16>();
		flags = *reader->read<uint32>();
		
		if (channel_info_len > 0)
		{
			reader->skip(channel_info_offset - reader->current_pos + header->beginning);
			reader->skip(channel_info_len);
		}	
		
		printf("File: %llu - %llu\n", persistent_file_id,  volatile_file_id);
		return SMB2_FileMessage::New();
	}	
	
	void SMB2_Write_Request::TriggerEvent()
	{
		SMB2_FileMessage::TriggerEvent();
		
		if (smb2_write_request) {	
			val_list* vl = create_value_list();

			mgr.QueueEvent(smb2_write_request, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	}
	
	bool SMB2_Write_Response::New()
	{		
		reader->skip(2);
		byte_count = *reader->read<uint32>();
		remaining = *reader->read<uint32>();
		channel_info_offset = *reader->read<uint16>();
		channel_info_len = *reader->read<uint16>();
		
		if (channel_info_len > 0)
		{
			reader->skip(channel_info_offset - reader->current_pos + header->beginning);
			reader->skip(channel_info_len);
		}	
		
		if (smb2_write_response) {	
			val_list* vl = create_value_list();

			mgr.QueueEvent(smb2_write_response, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}	
	
	bool SMB2_Cancel_Request::New()
	{		
		reader->move_end();
		
		if (smb2_cancel_request) {	
			val_list* vl = create_value_list();

			mgr.QueueEvent(smb2_cancel_request, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}	
	
	bool SMB2_Cancel_Response::New()
	{		
		reader->move_end();
		
		if (smb2_cancel_response) {	
			val_list* vl = create_value_list();

			mgr.QueueEvent(smb2_cancel_response, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}	
	
	bool SMB2_Query_Directory_Request::New()
	{		
		info_class = *reader->read<uint8>();
		flags = *reader->read<uint8>();
		file_index = *reader->read<uint32>();
		persistent_file_id = *reader->read<uint64>();
		volatile_file_id = *reader->read<uint64>();
		filename_offset = *reader->read<uint16>();
		filename_len = *reader->read<uint16>();
		output_buffer_len = *reader->read<uint32>();
		
		filename = NULL;
		if (filename_len > 0) {
			reader->skip(filename_offset - reader->current_pos + header->beginning);
			filename = reader->read_string(filename_len/2);
		}		
				
		if (smb2_query_directory_request) {	
			val_list* vl = create_value_list();

			mgr.QueueEvent(smb2_query_directory_request, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}		
	
		return true;
	}	
	
	bool SMB2_Query_Directory_Response::New()
	{		
		data_offset = *reader->read<uint16>();
		data_len = *reader->read<uint32>();
				
		if (!GetData())
			return false;
			
		TriggerEvent();
			
		return true;
	}	
	
	void SMB2_Query_Directory_Response::TriggerEvent()
	{
		if (smb2_query_directory_response) {	
			val_list* vl = create_value_list();

			mgr.QueueEvent(smb2_query_directory_response, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr, analyzer->Conn());		
		}				
	}
	
	void SMB2_Query_Directory_Response::ChunkReceived(uint32 length)
	{
		reader->skip(length);
	}
	
	void SMB2_Query_Directory_Response::ChunkFailed()
	{
	}
}